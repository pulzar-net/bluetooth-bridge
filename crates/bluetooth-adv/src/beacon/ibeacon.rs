//! Apple iBeacon: manufacturer data of company 0x004C, type 0x02, length 0x15.

use crate::reader::Reader;
use crate::uuid::Uuid;

#[cfg(feature = "serde")]
use serde::Serialize;

/// Apple's company identifier.
pub const COMPANY_ID: u16 = 0x004c;

/// An iBeacon frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct IBeacon {
    /// Proximity UUID.
    pub uuid: Uuid,
    /// Major.
    pub major: u16,
    /// Minor.
    pub minor: u16,
    /// Measured power: RSSI at one metre, dBm.
    pub measured_power: i8,
}

/// Decodes the manufacturer data (after the company identifier).
pub fn decode(company_id: u16, data: &[u8]) -> Option<IBeacon> {
    if company_id != COMPANY_ID {
        return None;
    }
    let mut r = Reader::new(data);
    if r.u8()? != 0x02 || r.u8()? != 0x15 {
        return None;
    }
    let uuid = Uuid::Uuid128(r.array()?);
    let b = IBeacon {
        uuid,
        major: r.u16_be()?,
        minor: r.u16_be()?,
        measured_power: r.i8()?,
    };
    Some(b)
}

/// Encodes an iBeacon as manufacturer data (after the company identifier),
/// for advertising one.
pub fn encode(b: &IBeacon) -> Vec<u8> {
    let mut v = vec![0x02, 0x15];
    v.extend_from_slice(&b.uuid.to_u128_bytes());
    v.extend_from_slice(&b.major.to_be_bytes());
    v.extend_from_slice(&b.minor.to_be_bytes());
    v.push(b.measured_power as u8);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data = hex::decode("0215e2c56db5dffb48d2b060d0f5a71096e000010002c5").unwrap();
        let b = decode(COMPANY_ID, &data).unwrap();
        assert_eq!(b.uuid.to_string(), "e2c56db5-dffb-48d2-b060-d0f5a71096e0");
        assert_eq!((b.major, b.minor, b.measured_power), (1, 2, -59));
        assert_eq!(encode(&b), data);
        assert!(decode(COMPANY_ID, &data[..10]).is_none());
        assert!(decode(0x0059, &data).is_none());
    }
}
