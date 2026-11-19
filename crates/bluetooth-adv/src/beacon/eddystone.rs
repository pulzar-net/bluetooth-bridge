//! Eddystone (<https://github.com/google/eddystone>): service data of UUID
//! 0xFEAA, first byte the frame type.

use super::Reading;
use crate::reader::Reader;

#[cfg(feature = "serde")]
use serde::Serialize;

/// Eddystone's service UUID.
pub const SERVICE_UUID: u16 = 0xfeaa;

/// An Eddystone frame.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(tag = "frame", rename_all = "snake_case")
)]
pub enum Eddystone {
    /// Eddystone-UID (0x00).
    Uid {
        /// Calibrated TX power at 0 m, dBm.
        tx_power: i8,
        /// 10-byte namespace.
        #[cfg_attr(feature = "serde", serde(serialize_with = "crate::ad::ser_hex"))]
        namespace: [u8; 10],
        /// 6-byte instance.
        #[cfg_attr(feature = "serde", serde(serialize_with = "crate::ad::ser_hex"))]
        instance: [u8; 6],
    },
    /// Eddystone-URL (0x10).
    Url {
        /// Calibrated TX power at 0 m, dBm.
        tx_power: i8,
        /// The URL, expanded.
        url: String,
    },
    /// Eddystone-TLM (0x20), version 0: telemetry in the clear.
    Tlm {
        /// Battery voltage, mV; `None` when the beacon does not measure it.
        battery_mv: Option<u16>,
        /// Temperature, °C; `None` when not supported (0x8000).
        temperature: Option<f64>,
        /// Advertising PDUs sent since power-on or reboot.
        adv_count: u32,
        /// Time since power-on or reboot, seconds (0.1 s resolution).
        uptime: f64,
    },
    /// Eddystone-TLM version 1 (encrypted, for EID beacons).
    EncryptedTlm {
        /// The encrypted telemetry.
        #[cfg_attr(feature = "serde", serde(serialize_with = "crate::ad::ser_hex"))]
        etlm: [u8; 12],
        /// Salt.
        salt: u16,
        /// Message integrity check.
        mic: u16,
    },
    /// Eddystone-EID (0x30): an ephemeral identifier.
    Eid {
        /// Calibrated TX power at 0 m, dBm.
        tx_power: i8,
        /// The 8-byte ephemeral identifier.
        #[cfg_attr(feature = "serde", serde(serialize_with = "crate::ad::ser_hex"))]
        eid: [u8; 8],
    },
}

const URL_SCHEMES: [&str; 4] = ["http://www.", "https://www.", "http://", "https://"];
const URL_EXPANSIONS: [&str; 14] = [
    ".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/", ".com", ".org", ".edu", ".net",
    ".info", ".biz", ".gov",
];

/// Decodes Eddystone service data; `None` for frame types Eddystone does not
/// define (KKM uses 0x21 and 0x22 under the same UUID).
pub fn decode(data: &[u8]) -> Option<Eddystone> {
    let mut r = Reader::new(data);
    match r.u8()? {
        0x00 => {
            let tx_power = r.i8()?;
            let namespace = r.array()?;
            let instance = r.array()?;
            // Two reserved bytes may follow; they carry nothing.
            Some(Eddystone::Uid {
                tx_power,
                namespace,
                instance,
            })
        }
        0x10 => {
            let tx_power = r.i8()?;
            let mut url = String::from(*URL_SCHEMES.get(usize::from(r.u8()?))?);
            for b in r.rest() {
                match URL_EXPANSIONS.get(usize::from(*b)) {
                    Some(e) => url.push_str(e),
                    None if (0x21..0x7f).contains(b) => url.push(char::from(*b)),
                    None => return None,
                }
            }
            Some(Eddystone::Url { tx_power, url })
        }
        0x20 => match r.u8()? {
            0x00 => {
                let vbatt = r.u16_be()?;
                let temp = r.i16_be()?;
                Some(Eddystone::Tlm {
                    battery_mv: (vbatt != 0).then_some(vbatt),
                    temperature: (temp != i16::MIN).then_some(f64::from(temp) / 256.0),
                    adv_count: r.u32_be()?,
                    uptime: f64::from(r.u32_be()?) / 10.0,
                })
            }
            0x01 => Some(Eddystone::EncryptedTlm {
                etlm: r.array()?,
                salt: r.u16_be()?,
                mic: r.u16_be()?,
            }),
            _ => None,
        },
        0x30 => Some(Eddystone::Eid {
            tx_power: r.i8()?,
            eid: r.array()?,
        }),
        _ => None,
    }
}

impl Eddystone {
    pub(crate) fn readings(&self) -> Vec<Reading> {
        match self {
            Eddystone::Tlm {
                battery_mv,
                temperature,
                adv_count,
                uptime,
            } => {
                let mut v = Vec::new();
                if let Some(b) = battery_mv {
                    v.push(Reading::new("voltage", f64::from(*b) / 1000.0, "V"));
                }
                if let Some(t) = temperature {
                    v.push(Reading::new("temperature", *t, "°C"));
                }
                v.push(Reading::new("adv_count", f64::from(*adv_count), ""));
                v.push(Reading::new("uptime", *uptime, "s"));
                v
            }
            _ => Vec::new(),
        }
    }
}

/// Encodes an Eddystone-URL frame's service data. `None` when the URL has no
/// Eddystone scheme or does not fit in 17 encoded bytes.
pub fn encode_url(tx_power: i8, url: &str) -> Option<Vec<u8>> {
    let (scheme, mut rest) = URL_SCHEMES
        .iter()
        .enumerate()
        .rev()
        .filter_map(|(i, s)| url.strip_prefix(s).map(|r| (i, r)))
        .max_by_key(|(i, _)| URL_SCHEMES[*i].len())?;
    let mut v = vec![0x10, tx_power as u8, scheme as u8];
    while !rest.is_empty() {
        if let Some((code, e)) = URL_EXPANSIONS
            .iter()
            .enumerate()
            .filter(|(_, e)| rest.starts_with(**e))
            .max_by_key(|(_, e)| e.len())
        {
            v.push(code as u8);
            rest = &rest[e.len()..];
        } else {
            let c = rest.as_bytes()[0];
            if !(0x21..0x7f).contains(&c) {
                return None;
            }
            v.push(c);
            rest = &rest[1..];
        }
    }
    (v.len() <= 20).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames() {
        let uid =
            decode(&hex::decode("00e8000102030405060708090a0b0c0d0e0f0000").unwrap()).unwrap();
        assert!(matches!(uid, Eddystone::Uid { tx_power: -24, .. }));
        let url = decode(&hex::decode("10f303676f6f676c6507").unwrap()).unwrap();
        assert_eq!(
            url,
            Eddystone::Url {
                tx_power: -13,
                url: "https://google.com".into()
            }
        );
        let tlm =
            decode(&hex::decode("2000 0bb8 1980 00000010 00000064".replace(' ', "")).unwrap())
                .unwrap();
        assert_eq!(
            tlm,
            Eddystone::Tlm {
                battery_mv: Some(3000),
                temperature: Some(25.5),
                adv_count: 16,
                uptime: 10.0
            }
        );
        let no_temp = decode(&hex::decode("200000008000000000000000000000").unwrap()).unwrap();
        assert!(matches!(
            no_temp,
            Eddystone::Tlm {
                battery_mv: None,
                temperature: None,
                ..
            }
        ));
        assert!(decode(&[0x21, 0, 0]).is_none());
        assert!(decode(&[0x10]).is_none());
    }

    #[test]
    fn url_round_trip() {
        for u in [
            "https://www.example.com/a",
            "http://pulse.example.org",
            "https://a.b/c.info",
        ] {
            let enc = encode_url(-20, u).unwrap();
            match decode(&enc).unwrap() {
                Eddystone::Url { url, .. } => assert_eq!(url, u),
                other => panic!("{other:?}"),
            }
        }
        assert!(encode_url(0, "ftp://x").is_none());
    }
}
