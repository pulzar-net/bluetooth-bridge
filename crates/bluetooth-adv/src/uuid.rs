//! Bluetooth UUIDs in their three wire sizes.

use core::fmt;

/// The Bluetooth Base UUID, `00000000-0000-1000-8000-00805F9B34FB`, most
/// significant byte first.
pub const BASE_UUID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// A Bluetooth UUID as it appeared on the wire: 16, 32 or 128 bits.
///
/// 16 and 32-bit UUIDs are shorthand for UUIDs on the Bluetooth Base UUID;
/// [`Uuid::to_u128_bytes`] expands them, and equality compares the expanded
/// forms, so `Uuid16(0x180f) == Uuid128(0000180f-0000-1000-8000-00805f9b34fb)`.
#[derive(Debug, Clone, Copy, Eq)]
pub enum Uuid {
    /// A 16-bit UUID.
    Uuid16(u16),
    /// A 32-bit UUID.
    Uuid32(u32),
    /// A 128-bit UUID, most significant byte first (as written).
    Uuid128([u8; 16]),
}

impl Uuid {
    /// Reads a UUID from its little-endian wire form, by length (2, 4 or 16 bytes).
    pub fn from_le_bytes(b: &[u8]) -> Option<Uuid> {
        match b.len() {
            2 => Some(Uuid::Uuid16(u16::from_le_bytes([b[0], b[1]]))),
            4 => Some(Uuid::Uuid32(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
            16 => {
                let mut a = [0u8; 16];
                for (i, x) in b.iter().rev().enumerate() {
                    a[i] = *x;
                }
                Some(Uuid::Uuid128(a))
            }
            _ => None,
        }
    }

    /// The little-endian wire form, in its own size.
    pub fn to_le_bytes(&self) -> Vec<u8> {
        match self {
            Uuid::Uuid16(v) => v.to_le_bytes().to_vec(),
            Uuid::Uuid32(v) => v.to_le_bytes().to_vec(),
            Uuid::Uuid128(a) => a.iter().rev().copied().collect(),
        }
    }

    /// The full 128-bit form, most significant byte first.
    pub fn to_u128_bytes(&self) -> [u8; 16] {
        match self {
            Uuid::Uuid16(v) => Self::expand(u32::from(*v)),
            Uuid::Uuid32(v) => Self::expand(*v),
            Uuid::Uuid128(a) => *a,
        }
    }

    fn expand(v: u32) -> [u8; 16] {
        let mut a = BASE_UUID;
        a[..4].copy_from_slice(&v.to_be_bytes());
        a
    }

    /// The shortest form: a 128-bit UUID on the Base UUID becomes 16 or 32 bits.
    pub fn shortened(&self) -> Uuid {
        let a = self.to_u128_bytes();
        if a[4..] == BASE_UUID[4..] {
            let v = u32::from_be_bytes([a[0], a[1], a[2], a[3]]);
            match u16::try_from(v) {
                Ok(s) => Uuid::Uuid16(s),
                Err(_) => Uuid::Uuid32(v),
            }
        } else {
            Uuid::Uuid128(a)
        }
    }

    /// The 16-bit value, when this UUID has one.
    pub fn as_u16(&self) -> Option<u16> {
        match self.shortened() {
            Uuid::Uuid16(v) => Some(v),
            _ => None,
        }
    }

    /// The SIG's name for this UUID, from the assigned numbers.
    pub fn name(&self) -> Option<&'static str> {
        self.as_u16()
            .and_then(bluetooth_numbers::uuid16)
            .map(|u| u.name)
    }

    /// Parses `180f`, `0x180f`, `0000180f` or the canonical
    /// `0000180f-0000-1000-8000-00805f9b34fb` form.
    pub fn parse(s: &str) -> Option<Uuid> {
        let s = s.trim();
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        match hex.len() {
            4 => u16::from_str_radix(&hex, 16).ok().map(Uuid::Uuid16),
            8 => u32::from_str_radix(&hex, 16).ok().map(Uuid::Uuid32),
            32 => {
                let v = hex::decode(&hex).ok()?;
                let a: [u8; 16] = v.try_into().ok()?;
                Some(Uuid::Uuid128(a))
            }
            _ => None,
        }
    }
}

impl PartialEq for Uuid {
    fn eq(&self, other: &Self) -> bool {
        self.to_u128_bytes() == other.to_u128_bytes()
    }
}

impl core::hash::Hash for Uuid {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_u128_bytes().hash(state);
    }
}

impl PartialOrd for Uuid {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Uuid {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_u128_bytes().cmp(&other.to_u128_bytes())
    }
}

impl From<u16> for Uuid {
    fn from(v: u16) -> Self {
        Uuid::Uuid16(v)
    }
}

impl fmt::Display for Uuid {
    /// 16 and 32-bit UUIDs print as 4 or 8 hex digits, 128-bit ones in the
    /// canonical hyphenated form; all lower case.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Uuid::Uuid16(v) => write!(f, "{v:04x}"),
            Uuid::Uuid32(v) => write!(f, "{v:08x}"),
            Uuid::Uuid128(a) => {
                let h = hex::encode(a);
                write!(
                    f,
                    "{}-{}-{}-{}-{}",
                    &h[0..8],
                    &h[8..12],
                    &h[12..16],
                    &h[16..20],
                    &h[20..32]
                )
            }
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Uuid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Uuid {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Uuid".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "A UUID: four hex digits for a 16-bit one (`180f`), eight for 32-bit, or the full 128-bit form (`0000180f-0000-1000-8000-00805f9b34fb`).",
            "examples": ["180f", "6e400001-b5a3-f393-e0a9-e50e24dcca9e"]
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Uuid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        Uuid::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("not a UUID: {s}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_and_equality() {
        let short = Uuid::Uuid16(0x180f);
        let long = Uuid::parse("0000180f-0000-1000-8000-00805f9b34fb").unwrap();
        assert_eq!(short, long);
        assert_eq!(long.shortened(), Uuid::Uuid16(0x180f));
        assert_eq!(short.to_string(), "180f");
        assert_eq!(long.to_string(), "0000180f-0000-1000-8000-00805f9b34fb");
        assert_eq!(Uuid::from_le_bytes(&[0x0f, 0x18]), Some(short));
        let wire = long.to_le_bytes();
        assert_eq!(Uuid::from_le_bytes(&wire), Some(long));
        assert_eq!(short.name(), Some("Battery"));
        assert_eq!(Uuid::parse("0x2A19"), Some(Uuid::Uuid16(0x2a19)));
        assert_eq!(Uuid::parse("nope"), None);
    }
}
