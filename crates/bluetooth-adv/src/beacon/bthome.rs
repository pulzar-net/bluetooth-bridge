//! BTHome v2 (<https://bthome.io/format/>): service data of UUID 0xFCD2.
//!
//! The first byte is the device information: bit 0 encryption, bit 2
//! trigger-based, bits 5 to 7 the version (2). Objects follow, each an object
//! id and a value whose size the id fixes. An encrypted frame is
//! AES-128-CCM with a 4-byte tag and the nonce
//! `MAC (6, as printed) || UUID (d2 fc) || device info || counter (4)`;
//! the counter and tag follow the ciphertext.
//!
//! A receiver must stop at an object id it does not know, since it cannot
//! know that object's size; [`BtHome::unknown_object`] says where that
//! happened.

use super::{Context, Reading};
use crate::reader::Reader;
use crate::AddressBytes;

use aes::Aes128;
use ccm::aead::{Aead, KeyInit, Payload};
use ccm::consts::{U13, U4};

#[cfg(feature = "serde")]
use serde::Serialize;

/// BTHome's service UUID.
pub const SERVICE_UUID: u16 = 0xfcd2;

type BtHomeCcm = ccm::Ccm<Aes128, U4, U13>;

/// A BTHome v2 frame.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct BtHome {
    /// The frame was encrypted.
    pub encrypted: bool,
    /// The frame was encrypted and could not be decrypted: no key, a wrong
    /// key, or no address to build the nonce from. Nothing else is set.
    pub undecryptable: bool,
    /// The encryption counter, when encrypted. A receiver should reject a
    /// counter that does not increase.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub counter: Option<u32>,
    /// The device sends at irregular intervals (on a button press, say).
    pub trigger_based: bool,
    /// The packet id (object 0x00): the same id twice is a repeat.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub packet_id: Option<u8>,
    /// Measurements and states.
    pub measurements: Vec<Measurement>,
    /// Button and dimmer events.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub events: Vec<Event>,
    /// Text objects (0x53).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub text: Vec<String>,
    /// Raw objects (0x54), hex.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub raw: Vec<String>,
    /// Device type id (0xF0).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub device_type: Option<u16>,
    /// Firmware version (0xF1 or 0xF2), dotted.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub firmware: Option<String>,
    /// The first object id this decoder does not know; decoding stopped there.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub unknown_object: Option<u8>,
    /// The frame ended inside an object.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "std::ops::Not::not"))]
    pub truncated: bool,
}

/// A measurement or state.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Measurement {
    /// The object id.
    pub object_id: u8,
    /// BTHome's name for it, snake case: `temperature`, `door`, ...
    pub name: &'static str,
    /// The value, scaled. Binary sensors are 0 or 1.
    pub value: f64,
    /// The unit, or empty.
    pub unit: &'static str,
}

/// A button or dimmer event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Event {
    /// `button` or `dimmer`.
    pub kind: &'static str,
    /// The event: `press`, `double_press`, `rotate_left`, ... or `none`.
    pub event: &'static str,
    /// For a dimmer, the number of steps.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub steps: Option<u8>,
    /// Which button or dimmer, counting from 1 in the order they appear.
    pub index: u8,
}

/// How an object's value is laid out.
#[derive(Clone, Copy)]
enum Kind {
    Unsigned(u8),
    Signed(u8),
}

/// (object id, name, layout, factor, unit). From the BTHome v2 format
/// specification; the ids must be listed in ascending order.
const OBJECTS: &[(u8, &str, Kind, f64, &str)] = {
    use Kind::{Signed as S, Unsigned as U};
    &[
        (0x01, "battery", U(1), 1.0, "%"),
        (0x02, "temperature", S(2), 0.01, "°C"),
        (0x03, "humidity", U(2), 0.01, "%"),
        (0x04, "pressure", U(3), 0.01, "hPa"),
        (0x05, "illuminance", U(3), 0.01, "lx"),
        (0x06, "mass", U(2), 0.01, "kg"),
        (0x07, "mass", U(2), 0.01, "lb"),
        (0x08, "dewpoint", S(2), 0.01, "°C"),
        (0x09, "count", U(1), 1.0, ""),
        (0x0a, "energy", U(3), 0.001, "kWh"),
        (0x0b, "power", U(3), 0.01, "W"),
        (0x0c, "voltage", U(2), 0.001, "V"),
        (0x0d, "pm2_5", U(2), 1.0, "µg/m³"),
        (0x0e, "pm10", U(2), 1.0, "µg/m³"),
        (0x0f, "generic_boolean", U(1), 1.0, ""),
        (0x10, "power_on", U(1), 1.0, ""),
        (0x11, "opening", U(1), 1.0, ""),
        (0x12, "co2", U(2), 1.0, "ppm"),
        (0x13, "tvoc", U(2), 1.0, "µg/m³"),
        (0x14, "moisture", U(2), 0.01, "%"),
        (0x15, "battery_low", U(1), 1.0, ""),
        (0x16, "battery_charging", U(1), 1.0, ""),
        (0x17, "carbon_monoxide", U(1), 1.0, ""),
        (0x18, "cold", U(1), 1.0, ""),
        (0x19, "connectivity", U(1), 1.0, ""),
        (0x1a, "door", U(1), 1.0, ""),
        (0x1b, "garage_door", U(1), 1.0, ""),
        (0x1c, "gas_detected", U(1), 1.0, ""),
        (0x1d, "heat", U(1), 1.0, ""),
        (0x1e, "light", U(1), 1.0, ""),
        (0x1f, "lock", U(1), 1.0, ""),
        (0x20, "moisture_detected", U(1), 1.0, ""),
        (0x21, "motion", U(1), 1.0, ""),
        (0x22, "moving", U(1), 1.0, ""),
        (0x23, "occupancy", U(1), 1.0, ""),
        (0x24, "plug", U(1), 1.0, ""),
        (0x25, "presence", U(1), 1.0, ""),
        (0x26, "problem", U(1), 1.0, ""),
        (0x27, "running", U(1), 1.0, ""),
        (0x28, "safety", U(1), 1.0, ""),
        (0x29, "smoke", U(1), 1.0, ""),
        (0x2a, "sound", U(1), 1.0, ""),
        (0x2b, "tamper", U(1), 1.0, ""),
        (0x2c, "vibration", U(1), 1.0, ""),
        (0x2d, "window", U(1), 1.0, ""),
        (0x2e, "humidity", U(1), 1.0, "%"),
        (0x2f, "moisture", U(1), 1.0, "%"),
        (0x3d, "count", U(2), 1.0, ""),
        (0x3e, "count", U(4), 1.0, ""),
        (0x3f, "rotation", S(2), 0.1, "°"),
        (0x40, "distance", U(2), 1.0, "mm"),
        (0x41, "distance", U(2), 0.1, "m"),
        (0x42, "duration", U(3), 0.001, "s"),
        (0x43, "current", U(2), 0.001, "A"),
        (0x44, "speed", U(2), 0.01, "m/s"),
        (0x45, "temperature", S(2), 0.1, "°C"),
        (0x46, "uv_index", U(1), 0.1, ""),
        (0x47, "volume", U(2), 0.1, "L"),
        (0x48, "volume", U(2), 1.0, "mL"),
        (0x49, "volume_flow_rate", U(2), 0.001, "m³/h"),
        (0x4a, "voltage", U(2), 0.1, "V"),
        (0x4b, "gas", U(3), 0.001, "m³"),
        (0x4c, "gas", U(4), 0.001, "m³"),
        (0x4d, "energy", U(4), 0.001, "kWh"),
        (0x4e, "volume", U(4), 0.001, "L"),
        (0x4f, "water", U(4), 0.001, "L"),
        (0x50, "timestamp", U(4), 1.0, "s"),
        (0x51, "acceleration", U(2), 0.001, "m/s²"),
        (0x52, "gyroscope", U(2), 0.001, "°/s"),
        (0x55, "volume_storage", U(4), 0.001, "L"),
        (0x56, "conductivity", U(2), 1.0, "µS/cm"),
        (0x57, "temperature", S(1), 1.0, "°C"),
        (0x58, "temperature", S(1), 0.35, "°C"),
        (0x59, "count", S(1), 1.0, ""),
        (0x5a, "count", S(2), 1.0, ""),
        (0x5b, "count", S(4), 1.0, ""),
        (0x5c, "power", S(4), 0.01, "W"),
        (0x5d, "current", S(2), 0.001, "A"),
        (0x5e, "direction", U(2), 0.01, "°"),
        (0x5f, "precipitation", U(2), 0.1, "mm"),
        (0x60, "channel", U(1), 1.0, ""),
        (0x61, "rotational_speed", U(2), 1.0, "rpm"),
    ]
};

const BUTTON_EVENTS: [&str; 7] = [
    "none",
    "press",
    "double_press",
    "triple_press",
    "long_press",
    "long_double_press",
    "long_triple_press",
];

/// Decodes BTHome service data (after the UUID). `None` when it is not v2.
pub fn decode(data: &[u8], ctx: &Context) -> Option<BtHome> {
    let (&info, body) = data.split_first()?;
    if info >> 5 != 2 {
        return None;
    }
    let mut out = BtHome {
        encrypted: info & 0x01 != 0,
        trigger_based: info & 0x04 != 0,
        ..BtHome::default()
    };
    if !out.encrypted {
        objects(body, &mut out);
        return Some(out);
    }
    // ciphertext || counter (4) || mic (4)
    if body.len() < 8 {
        out.undecryptable = true;
        out.truncated = true;
        return Some(out);
    }
    let (ct, tail) = body.split_at(body.len() - 8);
    let counter = [tail[0], tail[1], tail[2], tail[3]];
    out.counter = Some(u32::from_le_bytes(counter));
    let key = ctx
        .address
        .and_then(|a| ctx.bthome_keys.get(&a).map(|k| (a, k)));
    match key.and_then(|(addr, key)| {
        let mut sealed = ct.to_vec();
        sealed.extend_from_slice(&tail[4..]);
        BtHomeCcm::new(key.into())
            .decrypt(
                (&nonce(&addr, info, counter)).into(),
                Payload {
                    msg: &sealed,
                    aad: &[],
                },
            )
            .ok()
    }) {
        Some(plain) => objects(&plain, &mut out),
        None => out.undecryptable = true,
    }
    Some(out)
}

fn nonce(addr: &AddressBytes, info: u8, counter: [u8; 4]) -> [u8; 13] {
    let mut n = [0u8; 13];
    for (i, b) in addr.iter().rev().enumerate() {
        n[i] = *b;
    }
    n[6..8].copy_from_slice(&SERVICE_UUID.to_le_bytes());
    n[8] = info;
    n[9..].copy_from_slice(&counter);
    n
}

/// Encrypts a BTHome v2 payload (the objects, without the device info byte)
/// into service data, as a device would: for tests and for a gateway that
/// broadcasts BTHome itself.
pub fn encrypt(
    addr: &AddressBytes,
    key: &[u8; 16],
    info: u8,
    counter: u32,
    objects: &[u8],
) -> Vec<u8> {
    let info = info | 0x01;
    let c = counter.to_le_bytes();
    let sealed = BtHomeCcm::new(key.into())
        .encrypt(
            (&nonce(addr, info, c)).into(),
            Payload {
                msg: objects,
                aad: &[],
            },
        )
        .unwrap_or_default();
    let (ct, mic) = sealed.split_at(sealed.len().saturating_sub(4));
    let mut v = vec![info];
    v.extend_from_slice(ct);
    v.extend_from_slice(&c);
    v.extend_from_slice(mic);
    v
}

fn objects(data: &[u8], out: &mut BtHome) {
    let mut r = Reader::new(data);
    let (mut buttons, mut dimmers) = (0u8, 0u8);
    while let Some(id) = r.u8() {
        let ok = match id {
            0x00 => r.u8().map(|v| out.packet_id = Some(v)).is_some(),
            0x3a => r
                .u8()
                .map(|e| {
                    buttons = buttons.saturating_add(1);
                    out.events.push(Event {
                        kind: "button",
                        event: match e {
                            0x80 => "hold_press",
                            e => BUTTON_EVENTS
                                .get(usize::from(e))
                                .copied()
                                .unwrap_or("unknown"),
                        },
                        steps: None,
                        index: buttons,
                    });
                })
                .is_some(),
            0x3c => match (r.u8(), r.u8()) {
                (Some(e), Some(steps)) => {
                    dimmers = dimmers.saturating_add(1);
                    out.events.push(Event {
                        kind: "dimmer",
                        event: match e {
                            0 => "none",
                            1 => "rotate_left",
                            2 => "rotate_right",
                            _ => "unknown",
                        },
                        steps: Some(steps),
                        index: dimmers,
                    });
                    true
                }
                _ => false,
            },
            0x53 | 0x54 => match r.u8().and_then(|n| r.take(usize::from(n))) {
                Some(b) if id == 0x53 => {
                    out.text.push(String::from_utf8_lossy(b).into_owned());
                    true
                }
                Some(b) => {
                    out.raw.push(hex::encode(b));
                    true
                }
                None => false,
            },
            0xf0 => r.u16_le().map(|v| out.device_type = Some(v)).is_some(),
            0xf1 => r
                .array::<4>()
                .map(|v| out.firmware = Some(format!("{}.{}.{}.{}", v[3], v[2], v[1], v[0])))
                .is_some(),
            0xf2 => r
                .array::<3>()
                .map(|v| out.firmware = Some(format!("{}.{}.{}", v[2], v[1], v[0])))
                .is_some(),
            _ => {
                let Ok(i) = OBJECTS.binary_search_by_key(&id, |o| o.0) else {
                    out.unknown_object = Some(id);
                    return;
                };
                let (_, name, kind, factor, unit) = OBJECTS[i];
                let raw = match kind {
                    Kind::Unsigned(n) => r.uint_le(usize::from(n)).map(f64::from),
                    Kind::Signed(n) => r.sint_le(usize::from(n)).map(f64::from),
                };
                match raw {
                    Some(v) => {
                        out.measurements.push(Measurement {
                            object_id: id,
                            name,
                            value: round(v * factor, factor),
                            unit,
                        });
                        true
                    }
                    None => false,
                }
            }
        };
        if !ok {
            out.truncated = true;
            return;
        }
    }
}

/// Rounds away floating-point noise from scaling (`2506 * 0.01`).
fn round(v: f64, factor: f64) -> f64 {
    let digits = (-factor.log10()).ceil().max(0.0) as i32 + 1;
    let p = 10f64.powi(digits);
    (v * p).round() / p
}

impl BtHome {
    pub(crate) fn readings(&self) -> Vec<Reading> {
        let mut seen: Vec<(&str, u32)> = Vec::new();
        let mut v = Vec::new();
        for m in &self.measurements {
            let n = match seen.iter_mut().find(|(k, _)| *k == m.name) {
                Some((_, c)) => {
                    *c += 1;
                    *c
                }
                None => {
                    seen.push((m.name, 1));
                    1
                }
            };
            let key = if n == 1 {
                m.name.to_string()
            } else {
                format!("{}_{n}", m.name)
            };
            v.push(Reading::new(key, m.value, m.unit));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_frame() {
        // temperature 25.06 °C, humidity 50.55 %, battery 93 %, door open, button press.
        let data = hex::decode("40 00 0f 02ca09 03bf13 015d 1a01 3a01".replace(' ', "")).unwrap();
        let b = decode(&data, &Context::default()).unwrap();
        assert!(!b.encrypted);
        assert_eq!(b.packet_id, Some(15));
        let names: Vec<_> = b.measurements.iter().map(|m| (m.name, m.value)).collect();
        assert_eq!(
            names,
            vec![
                ("temperature", 25.06),
                ("humidity", 50.55),
                ("battery", 93.0),
                ("door", 1.0)
            ]
        );
        assert_eq!(b.events[0].event, "press");
        assert!(b.unknown_object.is_none());
    }

    #[test]
    fn stops_at_unknown_and_truncated() {
        let b = decode(&[0x40, 0x02, 0x01, 0xee, 0x01], &Context::default()).unwrap();
        assert!(b.truncated || b.unknown_object.is_some());
        let b = decode(&[0x40, 0x01, 0x10, 0xee, 0x01], &Context::default()).unwrap();
        assert_eq!(b.unknown_object, Some(0xee));
        assert_eq!(b.measurements.len(), 1);
        assert!(decode(&[0x20], &Context::default()).is_none());
        assert!(decode(&[], &Context::default()).is_none());
    }

    #[test]
    fn encrypted_round_trip() {
        let addr: AddressBytes = [0xa5, 0x80, 0x8f, 0xe6, 0x48, 0x54];
        let key = [0x23u8; 16];
        let data = encrypt(
            &addr,
            &key,
            0x40,
            0x0011_2233,
            &hex::decode("02ca0903bf13").unwrap(),
        );
        let mut ctx = Context::for_address(addr);
        let locked = decode(&data, &ctx).unwrap();
        assert!(locked.encrypted && locked.undecryptable);
        ctx.bthome_keys.insert(addr, key);
        let b = decode(&data, &ctx).unwrap();
        assert!(!b.undecryptable);
        assert_eq!(b.counter, Some(0x0011_2233));
        assert_eq!(b.measurements[0].value, 25.06);
        ctx.bthome_keys.insert(addr, [0x24; 16]);
        assert!(decode(&data, &ctx).unwrap().undecryptable);
    }

    #[test]
    fn objects_are_sorted() {
        assert!(OBJECTS.windows(2).all(|w| w[0].0 < w[1].0));
    }
}
