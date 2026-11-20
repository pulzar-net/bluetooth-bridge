#![doc = include_str!("../README.md")]

#![no_std]

include!(concat!(env!("OUT_DIR"), "/tables.rs"));

/// A 16-bit UUID's assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid16 {
    /// The UUID.
    pub uuid: u16,
    /// What kind of thing it names.
    pub kind: UuidKind,
    /// The SIG's name for it.
    pub name: &'static str,
    /// The SIG's identifier, such as `org.bluetooth.service.battery_service`,
    /// or empty where the SIG gives none (member and SDO UUIDs).
    pub id: &'static str,
}

/// The kinds of 16-bit UUID the SIG assigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UuidKind {
    /// A GATT service.
    Service,
    /// A GATT characteristic.
    Characteristic,
    /// A GATT descriptor.
    Descriptor,
    /// A GATT declaration (primary service, characteristic, ...).
    Declaration,
    /// A unit, used in the Characteristic Presentation Format.
    Unit,
    /// A UUID assigned to a SIG member company.
    Member,
    /// A UUID assigned to a standards body.
    Sdo,
    /// A BR/EDR service class (SDP).
    ServiceClass,
    /// A protocol identifier (SDP).
    Protocol,
    /// An Object Transfer object type.
    ObjectType,
    /// An SDP browse group.
    BrowseGroup,
    /// A Mesh profile.
    MeshProfile,
}

impl UuidKind {
    /// Every kind, in the order [`uuid16`] searches them.
    pub const ALL: [UuidKind; 12] = [
        UuidKind::Service,
        UuidKind::Characteristic,
        UuidKind::Descriptor,
        UuidKind::Declaration,
        UuidKind::Unit,
        UuidKind::Member,
        UuidKind::Sdo,
        UuidKind::ServiceClass,
        UuidKind::Protocol,
        UuidKind::ObjectType,
        UuidKind::BrowseGroup,
        UuidKind::MeshProfile,
    ];

    fn table(self) -> &'static [(u16, &'static str, &'static str)] {
        match self {
            UuidKind::Service => SERVICES,
            UuidKind::Characteristic => CHARACTERISTICS,
            UuidKind::Descriptor => DESCRIPTORS,
            UuidKind::Declaration => DECLARATIONS,
            UuidKind::Unit => UNITS,
            UuidKind::Member => MEMBERS,
            UuidKind::Sdo => SDOS,
            UuidKind::ServiceClass => SERVICE_CLASSES,
            UuidKind::Protocol => PROTOCOLS,
            UuidKind::ObjectType => OBJECT_TYPES,
            UuidKind::BrowseGroup => BROWSE_GROUPS,
            UuidKind::MeshProfile => MESH_PROFILES,
        }
    }

    /// The kind's name, in snake case, as used in JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            UuidKind::Service => "service",
            UuidKind::Characteristic => "characteristic",
            UuidKind::Descriptor => "descriptor",
            UuidKind::Declaration => "declaration",
            UuidKind::Unit => "unit",
            UuidKind::Member => "member",
            UuidKind::Sdo => "sdo",
            UuidKind::ServiceClass => "service_class",
            UuidKind::Protocol => "protocol",
            UuidKind::ObjectType => "object_type",
            UuidKind::BrowseGroup => "browse_group",
            UuidKind::MeshProfile => "mesh_profile",
        }
    }
}

fn find<T: Copy>(table: &'static [(u16, T)], key: u16) -> Option<T> {
    table
        .binary_search_by_key(&key, |e| e.0)
        .ok()
        .map(|i| table[i].1)
}

/// A 16-bit UUID of one kind.
pub fn uuid16_of(kind: UuidKind, uuid: u16) -> Option<Uuid16> {
    let table = kind.table();
    table
        .binary_search_by_key(&uuid, |e| e.0)
        .ok()
        .map(|i| Uuid16 {
            uuid,
            kind,
            name: table[i].1,
            id: table[i].2,
        })
}

/// A 16-bit UUID of any kind; services first, then characteristics and so on
/// (see [`UuidKind::ALL`]). The SIG's ranges do not overlap in practice.
pub fn uuid16(uuid: u16) -> Option<Uuid16> {
    UuidKind::ALL.iter().find_map(|k| uuid16_of(*k, uuid))
}

/// A GATT service.
pub fn service(uuid: u16) -> Option<Uuid16> {
    uuid16_of(UuidKind::Service, uuid)
}

/// A GATT characteristic.
pub fn characteristic(uuid: u16) -> Option<Uuid16> {
    uuid16_of(UuidKind::Characteristic, uuid)
}

/// A GATT descriptor.
pub fn descriptor(uuid: u16) -> Option<Uuid16> {
    uuid16_of(UuidKind::Descriptor, uuid)
}

/// A unit (Characteristic Presentation Format).
pub fn unit(uuid: u16) -> Option<Uuid16> {
    uuid16_of(UuidKind::Unit, uuid)
}

/// A UUID assigned to a member company, such as `0xFEAA` (Google, Eddystone).
pub fn member(uuid: u16) -> Option<Uuid16> {
    uuid16_of(UuidKind::Member, uuid)
}

/// The company a Company Identifier is assigned to (manufacturer specific data, LMP).
pub fn company(id: u16) -> Option<&'static str> {
    find(COMPANIES, id)
}

/// The name of an advertising data (AD) type.
pub fn ad_type(value: u8) -> Option<&'static str> {
    find(AD_TYPES, u16::from(value))
}

/// The scheme of the URI AD type's code point, such as `"https:"`.
pub fn uri_scheme(code: u16) -> Option<&'static str> {
    find(URI_SCHEMES, code)
}

/// A Bluetooth Core Specification version, as reported in HCI and LMP version fields.
pub fn core_version(value: u8) -> Option<&'static str> {
    find(CORE_VERSIONS, u16::from(value))
}

/// The protocol or profile assigned an L2CAP PSM.
pub fn psm(value: u16) -> Option<&'static str> {
    find(PSMS, value)
}

/// A Characteristic Presentation Format type: its short name and description.
pub fn format_type(value: u8) -> Option<(&'static str, &'static str)> {
    let key = u16::from(value);
    FORMAT_TYPES
        .binary_search_by_key(&key, |e| e.0)
        .ok()
        .map(|i| (FORMAT_TYPES[i].1, FORMAT_TYPES[i].2))
}

/// The name of a Mesh message opcode (1, 2 or 3 octets, as a number:
/// `0x8201` is Generic OnOff Get).
pub fn mesh_opcode(opcode: u32) -> Option<&'static str> {
    MESH_OPCODES
        .binary_search_by_key(&opcode, |e| e.0)
        .ok()
        .map(|i| MESH_OPCODES[i].1)
}

/// The name of a SIG Mesh model.
pub fn mesh_model(id: u16) -> Option<&'static str> {
    find(MESH_MODELS, id)
}

/// An Appearance value, split into its category and subcategory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appearance {
    /// The raw 16-bit value.
    pub value: u16,
    /// The category's name (bits 15 to 6), when assigned.
    pub category: Option<&'static str>,
    /// The subcategory's name (bits 5 to 0), when assigned; `None` for the
    /// generic subcategory 0.
    pub subcategory: Option<&'static str>,
}

/// Splits and names an Appearance value.
pub fn appearance(value: u16) -> Appearance {
    Appearance {
        value,
        category: find(APPEARANCE_CATEGORIES, value >> 6),
        subcategory: find(APPEARANCE_SUBCATEGORIES, value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_sorted_and_found() {
        for kind in UuidKind::ALL {
            let t = kind.table();
            assert!(t.windows(2).all(|w| w[0].0 < w[1].0), "{kind:?}");
        }
        assert!(COMPANIES.len() > 3000);
        assert_eq!(company(0x0000), Some("Ericsson AB"));
        assert_eq!(
            service(0x180f).unwrap().id,
            "org.bluetooth.service.battery_service"
        );
        assert_eq!(characteristic(0x2a19).unwrap().name, "Battery Level");
        assert_eq!(
            descriptor(0x2902).unwrap().name,
            "Client Characteristic Configuration"
        );
        assert_eq!(member(0xfeaa).unwrap().name, "Google LLC");
        assert_eq!(ad_type(0xff), Some("Manufacturer Specific Data"));
        assert_eq!(ad_type(0x01), Some("Flags"));
        assert_eq!(uri_scheme(0x0017), Some("https:"));
        assert!(core_version(0x0d).unwrap().contains("5.4"));
        assert_eq!(psm(0x0001), Some("SDP"));
        assert_eq!(format_type(0x06).unwrap().0, "uint16");
        let a = appearance(0x00c1);
        assert_eq!(a.category, Some("Watch"));
        assert_eq!(a.subcategory, Some("Sports Watch"));
        assert_eq!(uuid16(0x2a19).unwrap().kind, UuidKind::Characteristic);
        assert_eq!(mesh_opcode(0x8201), Some("Generic OnOff Get"));
        assert_eq!(mesh_opcode(0x00), Some("Config AppKey Add"));
        assert_eq!(mesh_model(0x0000), Some("Configuration Server"));
        assert_eq!(mesh_model(0x1000), Some("Generic OnOff Server"));
    }
}
