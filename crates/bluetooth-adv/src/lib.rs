#![doc = include_str!("../README.md")]
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

// The repository README's Rust examples run as doctests, so they cannot rot.
#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
struct ReadmeDoctests;
