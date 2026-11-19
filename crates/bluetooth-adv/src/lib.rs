//! Bluetooth LE advertising data, parsed and decoded.
//!
//! [`Advertisement::parse`] reads the AD structures of an advertisement or
//! scan response (Core Specification Supplement, Part A) into typed fields,
//! naming companies, UUIDs and appearance from the SIG's assigned numbers
//! ([`bluetooth_numbers`]). [`beacon::decode`] then recognises beacon and
//! sensor formats inside it.
//!
//! Nothing here panics on any input: advertisements come off the air from
//! devices nobody vetted, and every parser is fuzzed.
//!
//! ```
//! use bluetooth_adv::{Advertisement, beacon};
//! // Flags, then an iBeacon.
//! let data = hex::decode(
//!     "0201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000010002c5",
//! ).unwrap();
//! let adv = Advertisement::parse(&data);
//! let beacons = beacon::decode(&adv, &beacon::Context::default());
//! assert!(matches!(beacons[0], beacon::Beacon::IBeacon(_)));
//! ```
#![deny(unsafe_code)]

mod ad;
pub mod beacon;
mod reader;
mod uuid;

pub use ad::{
    AdStructure, AdStructures, Advertisement, DeviceId, Flags, LocalName, Malformed,
    ManufacturerData, ServiceData, ServiceUuid,
};
pub use uuid::Uuid;

/// A Bluetooth device address as it appears on the air and in HCI: least
/// significant byte first.
pub type AddressBytes = [u8; 6];

/// Formats an address, given least significant byte first, the usual way:
/// most significant byte first, colon separated, upper case.
pub fn format_address(addr: &AddressBytes) -> String {
    let mut s = String::with_capacity(17);
    for (i, b) in addr.iter().rev().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}
