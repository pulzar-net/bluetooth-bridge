//! AD structures (Core Specification Supplement, Part A) and the typed
//! [`Advertisement`] built from them.

use crate::reader::Reader;
use crate::uuid::Uuid;
use crate::AddressBytes;

#[cfg(feature = "serde")]
use serde::Serialize;

#[cfg(feature = "serde")]
pub(crate) fn ser_hex<S: serde::Serializer, T: AsRef<[u8]>>(
    v: &T,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v.as_ref()))
}

#[cfg(feature = "serde")]
fn ser_hex_opt<S: serde::Serializer, T: AsRef<[u8]>>(
    v: &Option<T>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => s.serialize_str(&hex::encode(v.as_ref())),
        None => s.serialize_none(),
    }
}

#[cfg(feature = "serde")]
fn ser_addrs<S: serde::Serializer>(v: &[AddressBytes], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(v.iter().map(crate::format_address))
}

/// One AD structure: a type and its data, borrowed from the advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdStructure<'a> {
    /// The AD type.
    pub ad_type: u8,
    /// The data after the type.
    pub data: &'a [u8],
}

impl AdStructure<'_> {
    /// The SIG's name for the AD type.
    pub fn type_name(&self) -> Option<&'static str> {
        bluetooth_numbers::ad_type(self.ad_type)
    }
}

/// Where an advertisement stopped making sense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Malformed {
    /// Offset of the structure whose length runs past the end of the data.
    pub offset: usize,
}

/// An iterator over the AD structures of advertising or scan response data.
///
/// A zero length octet ends the data early (the rest is padding, as the
/// Core Specification allows); a length running past the end yields one
/// [`Malformed`] and stops.
#[derive(Debug, Clone)]
pub struct AdStructures<'a> {
    data: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> AdStructures<'a> {
    /// Iterates over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for AdStructures<'a> {
    type Item = Result<AdStructure<'a>, Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.data.len() {
            return None;
        }
        let len = usize::from(self.data[self.offset]);
        if len == 0 {
            self.done = true;
            return None;
        }
        let start = self.offset + 1;
        let end = start + len;
        if end > self.data.len() {
            self.done = true;
            return Some(Err(Malformed {
                offset: self.offset,
            }));
        }
        self.offset = end;
        Some(Ok(AdStructure {
            ad_type: self.data[start],
            data: &self.data[start + 1..end],
        }))
    }
}

/// The Flags AD type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Flags {
    /// The raw octet.
    pub raw: u8,
    /// LE Limited Discoverable Mode.
    pub le_limited_discoverable: bool,
    /// LE General Discoverable Mode.
    pub le_general_discoverable: bool,
    /// BR/EDR Not Supported.
    pub br_edr_not_supported: bool,
    /// Simultaneous LE and BR/EDR to Same Device Capable (Controller).
    pub le_br_edr_controller: bool,
}

impl From<u8> for Flags {
    fn from(raw: u8) -> Self {
        Flags {
            raw,
            le_limited_discoverable: raw & 0x01 != 0,
            le_general_discoverable: raw & 0x02 != 0,
            br_edr_not_supported: raw & 0x04 != 0,
            le_br_edr_controller: raw & 0x08 != 0,
        }
    }
}

/// A service UUID listed in the advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ServiceUuid {
    /// The UUID.
    pub uuid: Uuid,
    /// Whether it came from a complete list (rather than an incomplete one).
    pub complete: bool,
    /// The SIG's name for it.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub name: Option<&'static str>,
}

/// The device's local name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LocalName {
    /// The name, with invalid UTF-8 replaced.
    pub name: String,
    /// Complete Local Name (rather than Shortened Local Name).
    pub complete: bool,
}

/// Service data: a UUID and the bytes the service defines.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ServiceData {
    /// The service UUID.
    pub uuid: Uuid,
    /// The SIG's name for the UUID.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub name: Option<&'static str>,
    /// The data.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub data: Vec<u8>,
}

/// Manufacturer specific data: a company identifier and the company's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ManufacturerData {
    /// The Company Identifier.
    pub company_id: u16,
    /// The company it is assigned to.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub company: Option<&'static str>,
    /// The data after the identifier.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub data: Vec<u8>,
}

/// The Device ID AD type (EIR): who made the device and which product it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct DeviceId {
    /// 1: Bluetooth SIG company identifier, 2: USB Implementer's Forum vendor id.
    pub vendor_id_source: u16,
    /// The vendor.
    pub vendor_id: u16,
    /// The product.
    pub product_id: u16,
    /// The product version.
    pub version: u16,
}

/// An AD structure kept as bytes: a type this crate names but whose contents
/// belong to another layer (Mesh, LE Audio, ...), or a type the SIG has not
/// assigned yet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct RawAd {
    /// The AD type.
    pub ad_type: u8,
    /// The SIG's name for it.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub name: Option<&'static str>,
    /// The data.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub data: Vec<u8>,
}

/// Every field an advertisement (or a scan response, or both concatenated)
/// can carry, read into typed values.
///
/// A field whose length is wrong for its type is kept in [`Advertisement::other`]
/// instead, so nothing the device sent is lost.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[non_exhaustive]
pub struct Advertisement {
    /// Flags.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub flags: Option<Flags>,
    /// Service UUIDs, 16, 32 and 128-bit, complete and incomplete lists.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub services: Vec<ServiceUuid>,
    /// Service Solicitation UUIDs.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub solicited_services: Vec<Uuid>,
    /// Shortened or Complete Local Name (the complete one wins).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub local_name: Option<LocalName>,
    /// Broadcast_Name (LE Audio broadcasts).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub broadcast_name: Option<String>,
    /// TX Power Level, dBm.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub tx_power: Option<i8>,
    /// Appearance, raw.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub appearance: Option<u16>,
    /// Appearance category and subcategory names.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub appearance_name: Option<String>,
    /// Class of Device (BR/EDR), 24 bits.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub class_of_device: Option<u32>,
    /// Device ID.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub device_id: Option<DeviceId>,
    /// Service Data, 16, 32 and 128-bit.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub service_data: Vec<ServiceData>,
    /// Manufacturer Specific Data (more than one is allowed in practice).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub manufacturer_data: Vec<ManufacturerData>,
    /// Peripheral Connection Interval Range, in 1.25 ms units; 0xFFFF means no bound.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub peripheral_connection_interval: Option<(u16, u16)>,
    /// Advertising Interval (or Advertising Interval - long), in 0.625 ms units.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub advertising_interval: Option<u32>,
    /// Public Target Addresses.
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Vec::is_empty", serialize_with = "ser_addrs")
    )]
    pub public_target_addresses: Vec<AddressBytes>,
    /// Random Target Addresses.
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Vec::is_empty", serialize_with = "ser_addrs")
    )]
    pub random_target_addresses: Vec<AddressBytes>,
    /// LE Bluetooth Device Address: the address, and whether it is random.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub le_address: Option<(String, bool)>,
    /// LE Role: 0 peripheral only, 1 central only, 2 both preferring
    /// peripheral, 3 both preferring central.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub le_role: Option<u8>,
    /// URI, with its scheme expanded from the assigned numbers.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub uri: Option<String>,
    /// LE Supported Features (bit mask, octet 0 first).
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_hex_opt"
        )
    )]
    pub le_supported_features: Option<Vec<u8>>,
    /// Resolvable Set Identifier (Coordinated Set Identification).
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_hex_opt"
        )
    )]
    pub resolvable_set_identifier: Option<[u8; 6]>,
    /// Security Manager TK Value (legacy OOB pairing).
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_hex_opt"
        )
    )]
    pub sm_tk: Option<[u8; 16]>,
    /// Security Manager Out of Band Flags.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub sm_oob_flags: Option<u8>,
    /// LE Secure Connections Confirmation Value (OOB).
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_hex_opt"
        )
    )]
    pub le_sc_confirmation: Option<[u8; 16]>,
    /// LE Secure Connections Random Value (OOB).
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_hex_opt"
        )
    )]
    pub le_sc_random: Option<[u8; 16]>,
    /// Simple Pairing Hash C-192 or C-256 (BR/EDR OOB), the last one seen.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_hex_opt"
        )
    )]
    pub ssp_hash: Option<[u8; 16]>,
    /// Simple Pairing Randomizer R-192 or R-256, the last one seen.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_hex_opt"
        )
    )]
    pub ssp_randomizer: Option<[u8; 16]>,
    /// Every other structure, by type, with its SIG name: Mesh, BIGInfo,
    /// Indoor Positioning, Transport Discovery, Encrypted Advertising Data,
    /// unassigned types, and any field whose length was wrong for its type.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub other: Vec<RawAd>,
    /// Set when a structure's length ran past the end of the data; every
    /// structure before it was still read.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub malformed: Option<Malformed>,
}

impl Advertisement {
    /// Reads every AD structure in `data`. Never fails: what cannot be read
    /// is kept as bytes or marked [`Advertisement::malformed`].
    pub fn parse(data: &[u8]) -> Advertisement {
        let mut adv = Advertisement::default();
        adv.extend(data);
        adv
    }

    /// Adds the structures in `data` (a scan response, say) to this advertisement.
    pub fn extend(&mut self, data: &[u8]) {
        for s in AdStructures::new(data) {
            match s {
                Ok(s) => {
                    if !self.add(s) {
                        self.other.push(RawAd {
                            ad_type: s.ad_type,
                            name: s.type_name(),
                            data: s.data.to_vec(),
                        });
                    }
                }
                Err(m) => self.malformed = Some(m),
            }
        }
    }

    /// Reads one structure into its field; `false` keeps it as raw bytes.
    fn add(&mut self, s: AdStructure<'_>) -> bool {
        let d = s.data;
        let mut r = Reader::new(d);
        match s.ad_type {
            0x01 => match d {
                [f, ..] => self.flags = Some(Flags::from(*f)),
                [] => return false,
            },
            0x02..=0x07 => {
                let size = match s.ad_type {
                    0x02 | 0x03 => 2,
                    0x04 | 0x05 => 4,
                    _ => 16,
                };
                if !d.len().is_multiple_of(size) {
                    return false;
                }
                let complete = s.ad_type % 2 == 1;
                for c in d.chunks_exact(size) {
                    if let Some(uuid) = Uuid::from_le_bytes(c) {
                        self.services.push(ServiceUuid {
                            uuid,
                            complete,
                            name: uuid.name(),
                        });
                    }
                }
            }
            0x14 | 0x15 | 0x1f => {
                let size = match s.ad_type {
                    0x14 => 2,
                    0x1f => 4,
                    _ => 16,
                };
                if !d.len().is_multiple_of(size) {
                    return false;
                }
                self.solicited_services
                    .extend(d.chunks_exact(size).filter_map(Uuid::from_le_bytes));
            }
            0x08 | 0x09 => {
                let complete = s.ad_type == 0x09;
                if complete || self.local_name.as_ref().is_none_or(|n| !n.complete) {
                    self.local_name = Some(LocalName {
                        name: String::from_utf8_lossy(d).into_owned(),
                        complete,
                    });
                }
            }
            0x30 => self.broadcast_name = Some(String::from_utf8_lossy(d).into_owned()),
            0x0a => match d {
                [p] => self.tx_power = Some(*p as i8),
                _ => return false,
            },
            0x0d => match d {
                [a, b, c] => self.class_of_device = Some(u32::from_le_bytes([*a, *b, *c, 0])),
                _ => return false,
            },
            0x10 => match d.len() {
                8 => {
                    self.device_id = Some(DeviceId {
                        vendor_id_source: r.u16_le().unwrap_or_default(),
                        vendor_id: r.u16_le().unwrap_or_default(),
                        product_id: r.u16_le().unwrap_or_default(),
                        version: r.u16_le().unwrap_or_default(),
                    })
                }
                16 => self.sm_tk = r.array(),
                _ => return false,
            },
            0x11 => match d {
                [f] => self.sm_oob_flags = Some(*f),
                _ => return false,
            },
            0x12 => match (r.u16_le(), r.u16_le(), r.remaining()) {
                (Some(min), Some(max), 0) => self.peripheral_connection_interval = Some((min, max)),
                _ => return false,
            },
            0x16 | 0x20 | 0x21 => {
                let size = match s.ad_type {
                    0x16 => 2,
                    0x20 => 4,
                    _ => 16,
                };
                let Some(uuid) = r.take(size).and_then(Uuid::from_le_bytes) else {
                    return false;
                };
                self.service_data.push(ServiceData {
                    uuid,
                    name: uuid.name(),
                    data: r.rest().to_vec(),
                });
            }
            0x17 | 0x18 => {
                if d.is_empty() || !d.len().is_multiple_of(6) {
                    return false;
                }
                let list = d
                    .chunks_exact(6)
                    .filter_map(|c| <AddressBytes>::try_from(c).ok());
                if s.ad_type == 0x17 {
                    self.public_target_addresses.extend(list);
                } else {
                    self.random_target_addresses.extend(list);
                }
            }
            0x19 => match r.u16_le() {
                Some(v) if r.remaining() == 0 => {
                    self.appearance = Some(v);
                    let a = bluetooth_numbers::appearance(v);
                    self.appearance_name = match (a.category, a.subcategory) {
                        (Some(c), Some(s)) => Some(format!("{c}: {s}")),
                        (Some(c), None) => Some(c.to_string()),
                        _ => None,
                    };
                }
                _ => return false,
            },
            0x1a | 0x2f => match d.len() {
                2..=4 => self.advertising_interval = r.uint_le(d.len()),
                _ => return false,
            },
            0x1b => match (r.array::<6>(), r.u8(), r.remaining()) {
                (Some(a), Some(t), 0) => {
                    self.le_address = Some((crate::format_address(&a), t & 1 == 1))
                }
                _ => return false,
            },
            0x1c => match d {
                [role] => self.le_role = Some(*role),
                _ => return false,
            },
            0x0e | 0x1d => match r.array() {
                Some(v) if r.remaining() == 0 => self.ssp_hash = Some(v),
                _ => return false,
            },
            0x0f | 0x1e => match r.array() {
                Some(v) if r.remaining() == 0 => self.ssp_randomizer = Some(v),
                _ => return false,
            },
            0x22 => match r.array() {
                Some(v) if r.remaining() == 0 => self.le_sc_confirmation = Some(v),
                _ => return false,
            },
            0x23 => match r.array() {
                Some(v) if r.remaining() == 0 => self.le_sc_random = Some(v),
                _ => return false,
            },
            0x24 => match decode_uri(d) {
                Some(u) => self.uri = Some(u),
                None => return false,
            },
            0x27 => self.le_supported_features = Some(d.to_vec()),
            0x2e => match r.array() {
                Some(v) if r.remaining() == 0 => self.resolvable_set_identifier = Some(v),
                _ => return false,
            },
            0xff => match r.u16_le() {
                Some(company_id) => self.manufacturer_data.push(ManufacturerData {
                    company_id,
                    company: bluetooth_numbers::company(company_id),
                    data: r.rest().to_vec(),
                }),
                None => return false,
            },
            _ => return false,
        }
        true
    }

    /// The service data for a UUID.
    pub fn service_data_for(&self, uuid: impl Into<Uuid>) -> Option<&[u8]> {
        let uuid = uuid.into();
        self.service_data
            .iter()
            .find(|s| s.uuid == uuid)
            .map(|s| s.data.as_slice())
    }

    /// The manufacturer data for a company.
    pub fn manufacturer_data_for(&self, company_id: u16) -> Option<&[u8]> {
        self.manufacturer_data
            .iter()
            .find(|m| m.company_id == company_id)
            .map(|m| m.data.as_slice())
    }
}

/// The URI AD type: the scheme is a UTF-8 encoded code point naming an
/// assigned URI scheme (0x01 for none), then the rest of the URI.
fn decode_uri(d: &[u8]) -> Option<String> {
    let s = core::str::from_utf8(d).ok()?;
    let mut chars = s.chars();
    let code = chars.next()? as u32;
    let rest = chars.as_str();
    if code == 0x01 {
        return Some(rest.to_string());
    }
    let scheme = bluetooth_numbers::uri_scheme(u16::try_from(code).ok()?)?;
    Some(format!("{scheme}{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structures_stop_at_padding_and_report_truncation() {
        let all: Vec<_> = AdStructures::new(&[2, 1, 6, 0, 9, 9]).collect();
        assert_eq!(
            all,
            vec![Ok(AdStructure {
                ad_type: 1,
                data: &[6]
            })]
        );
        let all: Vec<_> = AdStructures::new(&[2, 1, 6, 5, 9, b'a']).collect();
        assert_eq!(all[1], Err(Malformed { offset: 3 }));
        assert!(AdStructures::new(&[]).next().is_none());
    }

    #[test]
    fn parses_common_fields() {
        let data = hex_lit(concat!(
            "020106",                 // flags
            "0303 0f18",              // complete 16-bit: battery
            "0809 4b42 5072 6f2d 31", // "KBPro-1"
            "020a f4",                // tx -12
            "0319 c100",              // appearance: sports watch
            "0516 0f18 6400",         // service data battery
            "05ff 4c00 0102",         // apple
            "0524 17 2f2f 61",        // URI https://a  (0x17 is "https:")
            "03ee 0102",              // unassigned type
        ));
        let adv = Advertisement::parse(&data);
        assert!(adv.flags.unwrap().le_general_discoverable);
        assert_eq!(adv.services[0].uuid, Uuid::Uuid16(0x180f));
        assert!(adv.services[0].complete);
        assert_eq!(adv.local_name.as_ref().unwrap().name, "KBPro-1");
        assert_eq!(adv.tx_power, Some(-12));
        assert_eq!(adv.appearance_name.as_deref(), Some("Watch: Sports Watch"));
        assert_eq!(adv.service_data_for(0x180f), Some(&[0x64, 0x00][..]));
        assert_eq!(adv.manufacturer_data[0].company, Some("Apple, Inc."));
        assert_eq!(adv.uri.as_deref(), Some("https://a"));
        assert_eq!(adv.other[0].ad_type, 0xee);
        assert!(adv.malformed.is_none());
    }

    #[test]
    fn wrong_lengths_are_kept_raw() {
        let adv = Advertisement::parse(&hex_lit("030a0102 0219 01"));
        assert_eq!(adv.tx_power, None);
        assert_eq!(adv.other.len(), 2);
    }

    pub(crate) fn hex_lit(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }
}
