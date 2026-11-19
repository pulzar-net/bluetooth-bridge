//! Beacon and sensor formats found inside advertisements.
//!
//! | Format | Carried in | Module |
//! |---|---|---|
//! | iBeacon | Apple manufacturer data, type 0x02 | [`ibeacon`] |
//! | AltBeacon | any company's manufacturer data, code 0xBEAC | [`altbeacon`] |
//! | Eddystone UID, URL, TLM (plain and encrypted), EID | service data 0xFEAA | [`eddystone`] |
//! | BTHome v2, plain and encrypted | service data 0xFCD2 | [`bthome`] |
//! | KKM KBeacon sensor (v1, v2, encrypted) and system frames | service data 0xFEAA, manufacturer data 0x0A53 | [`kkm`] |
//! | Ruuvi RAWv1, RAWv2 (5), 6, E1 | manufacturer data 0x0499 | [`ruuvi`], decoded by the `ruuvi-sensor-protocol` crate |
//!
//! [`decode`] tries every format and returns all that match: one
//! advertisement can carry an iBeacon and an Eddystone TLM, say.

pub mod altbeacon;
pub mod bthome;
pub mod eddystone;
pub mod ibeacon;
pub mod kkm;
pub mod ruuvi;

use std::collections::HashMap;

use crate::{AddressBytes, Advertisement};

#[cfg(feature = "serde")]
use serde::Serialize;

/// What a decoder may need beyond the advertisement itself.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// The advertiser's address (least significant byte first): BTHome's
    /// nonce and KKM's key derivation include it. Without it encrypted
    /// frames are reported as encrypted but not decrypted.
    pub address: Option<AddressBytes>,
    /// BTHome bind keys by device address.
    pub bthome_keys: HashMap<AddressBytes, [u8; 16]>,
    /// KKM beacon passwords by device address (encrypted sensor frames).
    pub kkm_passwords: HashMap<AddressBytes, String>,
}

impl Context {
    /// A context for one advertiser, with no keys.
    pub fn for_address(address: AddressBytes) -> Self {
        Context {
            address: Some(address),
            ..Context::default()
        }
    }
}

/// A decoded beacon or sensor frame.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(tag = "format", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Beacon {
    /// Apple iBeacon.
    IBeacon(ibeacon::IBeacon),
    /// AltBeacon.
    AltBeacon(altbeacon::AltBeacon),
    /// Eddystone.
    Eddystone(eddystone::Eddystone),
    /// BTHome v2.
    BtHome(bthome::BtHome),
    /// KKM KBeacon.
    Kkm(kkm::Kkm),
    /// Ruuvi.
    Ruuvi(ruuvi::Ruuvi),
}

impl Beacon {
    /// The format's name, as used in the JSON `format` field.
    pub fn format(&self) -> &'static str {
        match self {
            Beacon::IBeacon(_) => "i_beacon",
            Beacon::AltBeacon(_) => "alt_beacon",
            Beacon::Eddystone(_) => "eddystone",
            Beacon::BtHome(_) => "bt_home",
            Beacon::Kkm(_) => "kkm",
            Beacon::Ruuvi(_) => "ruuvi",
        }
    }

    /// The measurements this frame carries, as (name, value, unit), for
    /// publishing sensors without knowing every format.
    pub fn readings(&self) -> Vec<Reading> {
        match self {
            Beacon::BtHome(b) => b.readings(),
            Beacon::Kkm(k) => k.readings(),
            Beacon::Ruuvi(r) => r.readings(),
            Beacon::Eddystone(e) => e.readings(),
            Beacon::IBeacon(_) | Beacon::AltBeacon(_) => Vec::new(),
        }
    }
}

/// One measurement from a sensor frame.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Reading {
    /// A stable snake_case key, unique within the frame (`temperature`,
    /// `button_2`, ...).
    pub key: String,
    /// The value.
    pub value: f64,
    /// The unit, as Home Assistant spells it (`°C`, `%`, `hPa`, ...), or empty.
    pub unit: &'static str,
}

impl Reading {
    pub(crate) fn new(key: impl Into<String>, value: f64, unit: &'static str) -> Self {
        Reading {
            key: key.into(),
            value,
            unit,
        }
    }
}

/// Every beacon format found in `adv`.
pub fn decode(adv: &Advertisement, ctx: &Context) -> Vec<Beacon> {
    let mut out = Vec::new();
    for m in &adv.manufacturer_data {
        if let Some(b) = ibeacon::decode(m.company_id, &m.data) {
            out.push(Beacon::IBeacon(b));
        }
        if let Some(b) = altbeacon::decode(m.company_id, &m.data) {
            out.push(Beacon::AltBeacon(b));
        }
        if let Some(b) = kkm::decode_manufacturer(m.company_id, &m.data, ctx) {
            out.push(Beacon::Kkm(b));
        }
        if let Some(b) = ruuvi::decode(m.company_id, &m.data) {
            out.push(Beacon::Ruuvi(b));
        }
    }
    for s in &adv.service_data {
        match s.uuid.as_u16() {
            Some(eddystone::SERVICE_UUID) => {
                if let Some(e) = eddystone::decode(&s.data) {
                    out.push(Beacon::Eddystone(e));
                } else if let Some(k) = kkm::decode_service_data(&s.data, ctx) {
                    out.push(Beacon::Kkm(k));
                }
            }
            Some(bthome::SERVICE_UUID) => {
                if let Some(b) = bthome::decode(&s.data, ctx) {
                    out.push(Beacon::BtHome(b));
                }
            }
            _ => {}
        }
    }
    out
}
