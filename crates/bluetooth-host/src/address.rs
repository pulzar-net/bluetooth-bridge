//! Device addresses (Core Vol 6, Part B, 1.3).

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

/// Public or random.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressType {
    /// An IEEE-assigned public address.
    Public,
    /// A random address: static, resolvable private, or non-resolvable private.
    Random,
}

/// What a random address is, from its two most significant bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomKind {
    /// `11`: static, the same until the device power cycles or chooses to change it.
    Static,
    /// `01`: resolvable private address (RPA), resolved with the device's IRK.
    Resolvable,
    /// `00`: non-resolvable private address.
    NonResolvable,
    /// `10`: reserved.
    Reserved,
}

/// A Bluetooth LE device address: type and the six bytes, least significant first
/// (as on the air and in HCI).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    /// Public or random.
    pub kind: AddressType,
    /// The bytes, least significant first.
    pub bytes: [u8; 6],
}

impl Address {
    /// A public address.
    pub const fn public(bytes: [u8; 6]) -> Self {
        Address {
            kind: AddressType::Public,
            bytes,
        }
    }

    /// A random address.
    pub const fn random(bytes: [u8; 6]) -> Self {
        Address {
            kind: AddressType::Random,
            bytes,
        }
    }

    /// For a random address, which kind.
    pub fn random_kind(&self) -> Option<RandomKind> {
        (self.kind == AddressType::Random).then(|| match self.bytes[5] >> 6 {
            0b11 => RandomKind::Static,
            0b01 => RandomKind::Resolvable,
            0b00 => RandomKind::NonResolvable,
            _ => RandomKind::Reserved,
        })
    }

    /// A resolvable private address, which a stored IRK may resolve to an identity.
    pub fn is_resolvable(&self) -> bool {
        self.random_kind() == Some(RandomKind::Resolvable)
    }

    /// The HCI address type octet: 0 public, 1 random.
    pub fn hci_type(&self) -> u8 {
        match self.kind {
            AddressType::Public => 0,
            AddressType::Random => 1,
        }
    }

    /// From an HCI address type octet. 2 and 3 (identity addresses the
    /// controller resolved) map to public and random.
    pub fn from_hci(kind: u8, bytes: [u8; 6]) -> Self {
        Address {
            kind: if kind & 1 == 0 {
                AddressType::Public
            } else {
                AddressType::Random
            },
            bytes,
        }
    }

    /// A fresh static random address.
    pub fn new_static_random() -> Self {
        let mut b = [0u8; 6];
        crate::crypto::random_bytes(&mut b);
        b[5] |= 0xc0;
        Address::random(b)
    }
}

impl fmt::Display for Address {
    /// `AA:BB:CC:DD:EE:FF`, most significant byte first.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.bytes;
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            b[5], b[4], b[3], b[2], b[1], b[0]
        )
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            AddressType::Public => write!(f, "{self}"),
            AddressType::Random => write!(f, "{self}/random"),
        }
    }
}

/// An address that could not be parsed.
#[derive(Debug, Clone, thiserror::Error)]
#[error("not a Bluetooth address: {0:?} (want AA:BB:CC:DD:EE:FF, optionally /public or /random)")]
pub struct AddressParseError(String);

impl FromStr for Address {
    type Err = AddressParseError;

    /// `AA:BB:CC:DD:EE:FF` (public), with `/random` or `/public` to say which.
    /// Hyphens or no separators are accepted too.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || AddressParseError(s.to_string());
        let (addr, kind) = match s.rsplit_once('/') {
            Some((a, "random")) => (a, AddressType::Random),
            Some((a, "public")) => (a, AddressType::Public),
            Some(_) => return Err(err()),
            None => (s, AddressType::Public),
        };
        let hex: String = addr.chars().filter(|c| *c != ':' && *c != '-').collect();
        let v = hex::decode(&hex).map_err(|_| err())?;
        let mut bytes: [u8; 6] = v.try_into().map_err(|_| err())?;
        bytes.reverse();
        Ok(Address { kind, bytes })
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&format_args!("{self:?}"))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_print() {
        let a: Address = "C0:11:22:33:44:55/random".parse().unwrap();
        assert_eq!(a.bytes, [0x55, 0x44, 0x33, 0x22, 0x11, 0xc0]);
        assert_eq!(a.random_kind(), Some(RandomKind::Static));
        assert_eq!(a.to_string(), "C0:11:22:33:44:55");
        assert_eq!(format!("{a:?}"), "C0:11:22:33:44:55/random");
        let p: Address = "bc5729000001".parse().unwrap();
        assert_eq!(p.kind, AddressType::Public);
        assert!(p.random_kind().is_none());
        assert!("zz".parse::<Address>().is_err());
        assert!(Address::new_static_random().random_kind() == Some(RandomKind::Static));
    }
}
