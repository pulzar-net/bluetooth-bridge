//! GATT (Core Vol 3, Part G): a client for peers' servers, and our own server.

pub mod client;
pub mod server;

use bluetooth_adv::Uuid;
use serde::{Deserialize, Serialize};

/// Well-known attribute types.
pub mod uuid {
    /// Primary Service declaration.
    pub const PRIMARY_SERVICE: u16 = 0x2800;
    /// Secondary Service declaration.
    pub const SECONDARY_SERVICE: u16 = 0x2801;
    /// Include declaration.
    pub const INCLUDE: u16 = 0x2802;
    /// Characteristic declaration.
    pub const CHARACTERISTIC: u16 = 0x2803;
    /// Characteristic Extended Properties.
    pub const EXTENDED_PROPERTIES: u16 = 0x2900;
    /// Characteristic User Description.
    pub const USER_DESCRIPTION: u16 = 0x2901;
    /// Client Characteristic Configuration.
    pub const CCCD: u16 = 0x2902;
    /// Server Characteristic Configuration.
    pub const SCCD: u16 = 0x2903;
    /// Characteristic Presentation Format.
    pub const PRESENTATION_FORMAT: u16 = 0x2904;
    /// Characteristic Aggregate Format.
    pub const AGGREGATE_FORMAT: u16 = 0x2905;
    /// GAP service.
    pub const GAP: u16 = 0x1800;
    /// GATT service.
    pub const GATT: u16 = 0x1801;
    /// Device Name.
    pub const DEVICE_NAME: u16 = 0x2a00;
    /// Appearance.
    pub const APPEARANCE: u16 = 0x2a01;
    /// Service Changed.
    pub const SERVICE_CHANGED: u16 = 0x2a05;
    /// Central Address Resolution.
    pub const CENTRAL_ADDRESS_RESOLUTION: u16 = 0x2aa6;
    /// Client Supported Features.
    pub const CLIENT_SUPPORTED_FEATURES: u16 = 0x2b29;
    /// Database Hash.
    pub const DATABASE_HASH: u16 = 0x2b2a;
    /// Server Supported Features.
    pub const SERVER_SUPPORTED_FEATURES: u16 = 0x2b3a;
}

/// Characteristic properties (the declaration's bit field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct Properties(pub u8);

impl Properties {
    /// Broadcast.
    pub const BROADCAST: u8 = 0x01;
    /// Read.
    pub const READ: u8 = 0x02;
    /// Write Without Response.
    pub const WRITE_WITHOUT_RESPONSE: u8 = 0x04;
    /// Write.
    pub const WRITE: u8 = 0x08;
    /// Notify.
    pub const NOTIFY: u8 = 0x10;
    /// Indicate.
    pub const INDICATE: u8 = 0x20;
    /// Authenticated Signed Writes.
    pub const SIGNED_WRITE: u8 = 0x40;
    /// Extended Properties.
    pub const EXTENDED: u8 = 0x80;

    /// Whether a bit is set.
    pub fn has(&self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// The property names, for reports.
    pub fn names(&self) -> Vec<&'static str> {
        [
            (Self::BROADCAST, "broadcast"),
            (Self::READ, "read"),
            (Self::WRITE_WITHOUT_RESPONSE, "write_without_response"),
            (Self::WRITE, "write"),
            (Self::NOTIFY, "notify"),
            (Self::INDICATE, "indicate"),
            (Self::SIGNED_WRITE, "authenticated_signed_writes"),
            (Self::EXTENDED, "extended_properties"),
        ]
        .iter()
        .filter(|(b, _)| self.has(*b))
        .map(|(_, n)| *n)
        .collect()
    }

    /// From property names (as [`Properties::names`] gives them).
    pub fn from_names<S: AsRef<str>>(names: &[S]) -> Result<Properties, String> {
        let mut p = 0;
        for n in names {
            p |= match n.as_ref() {
                "broadcast" => Self::BROADCAST,
                "read" => Self::READ,
                "write_without_response" => Self::WRITE_WITHOUT_RESPONSE,
                "write" => Self::WRITE,
                "notify" => Self::NOTIFY,
                "indicate" => Self::INDICATE,
                "authenticated_signed_writes" => Self::SIGNED_WRITE,
                other => return Err(format!("unknown characteristic property {other:?}")),
            };
        }
        Ok(Properties(p))
    }
}

/// A service on a peer's server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Service {
    /// Its UUID.
    pub uuid: Uuid,
    /// The SIG's name for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'static str>,
    /// Primary (rather than secondary, found through an include).
    pub primary: bool,
    /// The declaration's handle.
    pub start: u16,
    /// The last handle in the service.
    pub end: u16,
    /// Its characteristics, when discovered.
    pub characteristics: Vec<Characteristic>,
}

/// A characteristic on a peer's server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Characteristic {
    /// Its UUID.
    pub uuid: Uuid,
    /// The SIG's name for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'static str>,
    /// The declaration's handle.
    pub declaration: u16,
    /// The value's handle (what reads and writes address).
    pub value_handle: u16,
    /// Properties.
    pub properties: Properties,
    /// The last handle belonging to the characteristic.
    pub end: u16,
    /// Descriptors, when discovered.
    pub descriptors: Vec<Descriptor>,
}

impl Characteristic {
    /// The Client Characteristic Configuration descriptor's handle, if found.
    pub fn cccd(&self) -> Option<u16> {
        self.descriptors
            .iter()
            .find(|d| d.uuid == Uuid::Uuid16(uuid::CCCD))
            .map(|d| d.handle)
    }
}

/// A descriptor on a peer's server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Descriptor {
    /// Its UUID.
    pub uuid: Uuid,
    /// Its handle.
    pub handle: u16,
}

pub(crate) fn uuid_bytes(u: &Uuid) -> Vec<u8> {
    match u.shortened() {
        Uuid::Uuid16(v) => v.to_le_bytes().to_vec(),
        // ATT carries only 16 and 128-bit UUIDs.
        other => {
            let mut a = other.to_u128_bytes();
            a.reverse();
            a.to_vec()
        }
    }
}
