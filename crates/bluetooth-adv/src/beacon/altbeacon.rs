//! AltBeacon (<https://github.com/AltBeacon/spec>): manufacturer data of any
//! company, beacon code 0xBEAC, a 20-byte beacon id, reference RSSI and one
//! reserved byte.

use crate::reader::Reader;

#[cfg(feature = "serde")]
use serde::Serialize;

/// An AltBeacon frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct AltBeacon {
    /// The advertiser's company identifier.
    pub company_id: u16,
    /// Beacon id: by convention a 16-byte organisational unit then 4 bytes.
    #[cfg_attr(feature = "serde", serde(serialize_with = "crate::ad::ser_hex"))]
    pub beacon_id: [u8; 20],
    /// Average RSSI at one metre, dBm.
    pub reference_rssi: i8,
    /// Reserved for the manufacturer.
    pub reserved: u8,
}

/// Decodes the manufacturer data (after the company identifier).
pub fn decode(company_id: u16, data: &[u8]) -> Option<AltBeacon> {
    let mut r = Reader::new(data);
    if r.u16_be()? != 0xbeac || data.len() != 24 {
        return None;
    }
    Some(AltBeacon {
        company_id,
        beacon_id: r.array()?,
        reference_rssi: r.i8()?,
        reserved: r.u8()?,
    })
}

/// Encodes an AltBeacon as manufacturer data (after the company identifier).
pub fn encode(b: &AltBeacon) -> Vec<u8> {
    let mut v = vec![0xbe, 0xac];
    v.extend_from_slice(&b.beacon_id);
    v.push(b.reference_rssi as u8);
    v.push(b.reserved);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data = hex::decode("beac2f234454cf6d4a0fadf2f4911ba9ffa600010002c500").unwrap();
        let b = decode(0x0118, &data).unwrap();
        assert_eq!(b.reference_rssi, -59);
        assert_eq!(encode(&b), data);
        assert!(decode(0x0118, &data[..23]).is_none());
    }
}
