//! The access layer (Mesh Protocol 3.7): opcodes and the messages of the
//! foundation models (Configuration, sent with the device key) and of the
//! Generic OnOff and Level models. Opcode names come from the SIG's
//! assigned numbers ([`bluetooth_numbers::mesh_opcode`]).

/// An opcode: 1 octet (`0x00`-`0x7e`), 2 octets (`0x8000`-`0xbfff`), or 3
/// octets (`0xc0xxxx`, a vendor's, with its company identifier).
pub type Opcode = u32;

/// Splits an access payload into opcode and parameters.
pub fn split(payload: &[u8]) -> Option<(Opcode, &[u8])> {
    let (&b0, _) = payload.split_first()?;
    match b0 {
        0x7f => None, // reserved for future use
        0x00..=0x7e => Some((u32::from(b0), &payload[1..])),
        0x80..=0xbf => {
            let b1 = *payload.get(1)?;
            Some((u32::from_be_bytes([0, 0, b0, b1]), &payload[2..]))
        }
        _ => {
            let r = payload.get(1..3)?;
            Some((u32::from_be_bytes([0, b0, r[0], r[1]]), &payload[3..]))
        }
    }
}

/// An access payload: opcode then parameters.
pub fn message(opcode: Opcode, params: &[u8]) -> Vec<u8> {
    let mut v = match opcode {
        0..=0x7e => vec![opcode as u8],
        0x8000..=0xbfff => (opcode as u16).to_be_bytes().to_vec(),
        _ => opcode.to_be_bytes()[1..].to_vec(),
    };
    v.extend_from_slice(params);
    v
}

/// The opcode's name.
pub fn name(opcode: Opcode) -> Option<&'static str> {
    bluetooth_numbers::mesh_opcode(opcode)
}

/// Configuration and Generic opcodes the provisioner uses.
pub mod op {
    use super::Opcode;
    /// Config AppKey Add.
    pub const APPKEY_ADD: Opcode = 0x00;
    /// Config AppKey Status.
    pub const APPKEY_STATUS: Opcode = 0x8003;
    /// Config Composition Data Get.
    pub const COMPOSITION_GET: Opcode = 0x8008;
    /// Config Composition Data Status.
    pub const COMPOSITION_STATUS: Opcode = 0x02;
    /// Config Default TTL Get.
    pub const DEFAULT_TTL_GET: Opcode = 0x800c;
    /// Config Default TTL Status.
    pub const DEFAULT_TTL_STATUS: Opcode = 0x800e;
    /// Config Model App Bind.
    pub const MODEL_APP_BIND: Opcode = 0x803d;
    /// Config Model App Status.
    pub const MODEL_APP_STATUS: Opcode = 0x803e;
    /// Config Model Publication Set.
    pub const MODEL_PUB_SET: Opcode = 0x03;
    /// Config Model Publication Status.
    pub const MODEL_PUB_STATUS: Opcode = 0x8019;
    /// Config Model Subscription Add.
    pub const MODEL_SUB_ADD: Opcode = 0x801b;
    /// Config Model Subscription Status.
    pub const MODEL_SUB_STATUS: Opcode = 0x801f;
    /// Config Node Reset.
    pub const NODE_RESET: Opcode = 0x8049;
    /// Config Node Reset Status.
    pub const NODE_RESET_STATUS: Opcode = 0x804a;
    /// Generic OnOff Get.
    pub const ONOFF_GET: Opcode = 0x8201;
    /// Generic OnOff Set.
    pub const ONOFF_SET: Opcode = 0x8202;
    /// Generic OnOff Set Unacknowledged.
    pub const ONOFF_SET_UNACK: Opcode = 0x8203;
    /// Generic OnOff Status.
    pub const ONOFF_STATUS: Opcode = 0x8204;
    /// Generic Level Get.
    pub const LEVEL_GET: Opcode = 0x8205;
    /// Generic Level Set.
    pub const LEVEL_SET: Opcode = 0x8206;
    /// Generic Level Set Unacknowledged.
    pub const LEVEL_SET_UNACK: Opcode = 0x8207;
    /// Generic Level Status.
    pub const LEVEL_STATUS: Opcode = 0x8208;
}

/// Two 12-bit key indexes packed in three octets, little-endian.
pub fn key_indexes(net: u16, app: u16) -> [u8; 3] {
    let v = u32::from(net & 0xfff) | (u32::from(app & 0xfff) << 12);
    [v as u8, (v >> 8) as u8, (v >> 16) as u8]
}

/// Config AppKey Add.
pub fn appkey_add(net_index: u16, app_index: u16, app_key: &[u8; 16]) -> Vec<u8> {
    let mut p = key_indexes(net_index, app_index).to_vec();
    p.extend_from_slice(app_key);
    message(op::APPKEY_ADD, &p)
}

/// A model: a SIG model (16 bits) or a vendor's (company, model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelId {
    /// A SIG model.
    Sig(u16),
    /// A vendor model: company identifier, model.
    Vendor(u16, u16),
}

impl ModelId {
    fn bytes(&self) -> Vec<u8> {
        match self {
            ModelId::Sig(m) => m.to_le_bytes().to_vec(),
            ModelId::Vendor(c, m) => {
                let mut v = c.to_le_bytes().to_vec();
                v.extend_from_slice(&m.to_le_bytes());
                v
            }
        }
    }

    /// The SIG's name for a SIG model.
    pub fn name(&self) -> Option<&'static str> {
        match self {
            ModelId::Sig(m) => bluetooth_numbers::mesh_model(*m),
            ModelId::Vendor(..) => None,
        }
    }
}

/// Config Model App Bind.
pub fn model_app_bind(element: u16, app_index: u16, model: ModelId) -> Vec<u8> {
    let mut p = element.to_le_bytes().to_vec();
    p.extend_from_slice(&(app_index & 0xfff).to_le_bytes());
    p.extend(model.bytes());
    message(op::MODEL_APP_BIND, &p)
}

/// Config Model Subscription Add.
pub fn model_sub_add(element: u16, group: u16, model: ModelId) -> Vec<u8> {
    let mut p = element.to_le_bytes().to_vec();
    p.extend_from_slice(&group.to_le_bytes());
    p.extend(model.bytes());
    message(op::MODEL_SUB_ADD, &p)
}

/// Config Model Publication Set: publish to `address` with `app_index`,
/// TTL, period (raw byte), retransmit count and interval steps.
pub fn model_pub_set(
    element: u16,
    address: u16,
    app_index: u16,
    ttl: u8,
    period: u8,
    model: ModelId,
) -> Vec<u8> {
    let mut p = element.to_le_bytes().to_vec();
    p.extend_from_slice(&address.to_le_bytes());
    p.extend_from_slice(&(app_index & 0xfff).to_le_bytes());
    p.push(ttl);
    p.push(period);
    p.push(0); // no retransmissions
    p.extend(model.bytes());
    message(op::MODEL_PUB_SET, &p)
}

/// One element of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// Location descriptor.
    pub location: u16,
    /// Its models.
    pub models: Vec<ModelId>,
}

/// Composition Data page 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composition {
    /// Company identifier.
    pub cid: u16,
    /// Product identifier.
    pub pid: u16,
    /// Version identifier.
    pub vid: u16,
    /// Replay protection list size.
    pub crpl: u16,
    /// Features: relay, proxy, friend, low power (bits 0-3).
    pub features: u16,
    /// Elements, the primary first.
    pub elements: Vec<Element>,
}

impl Composition {
    /// Parses a Config Composition Data Status's parameters (page then data).
    pub fn parse(params: &[u8]) -> Option<Composition> {
        let (&page, d) = params.split_first()?;
        if page != 0 || d.len() < 10 {
            return None;
        }
        let u = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]);
        let mut c = Composition {
            cid: u(0),
            pid: u(2),
            vid: u(4),
            crpl: u(6),
            features: u(8),
            elements: Vec::new(),
        };
        let mut r = &d[10..];
        while !r.is_empty() {
            if r.len() < 4 {
                return None;
            }
            let (loc, ns, nv) = (
                u16::from_le_bytes([r[0], r[1]]),
                usize::from(r[2]),
                usize::from(r[3]),
            );
            let need = 4 + 2 * ns + 4 * nv;
            if r.len() < need {
                return None;
            }
            let mut models = Vec::with_capacity(ns + nv);
            for i in 0..ns {
                models.push(ModelId::Sig(u16::from_le_bytes([
                    r[4 + 2 * i],
                    r[5 + 2 * i],
                ])));
            }
            for i in 0..nv {
                let o = 4 + 2 * ns + 4 * i;
                models.push(ModelId::Vendor(
                    u16::from_le_bytes([r[o], r[o + 1]]),
                    u16::from_le_bytes([r[o + 2], r[o + 3]]),
                ));
            }
            c.elements.push(Element {
                location: loc,
                models,
            });
            r = &r[need..];
        }
        Some(c)
    }
}

/// Generic OnOff Set (or Set Unacknowledged): on or off, with a
/// transaction identifier.
pub fn onoff_set(on: bool, tid: u8, acknowledged: bool) -> Vec<u8> {
    message(
        if acknowledged {
            op::ONOFF_SET
        } else {
            op::ONOFF_SET_UNACK
        },
        &[u8::from(on), tid],
    )
}

/// Generic Level Set (or Set Unacknowledged).
pub fn level_set(level: i16, tid: u8, acknowledged: bool) -> Vec<u8> {
    let mut p = level.to_le_bytes().to_vec();
    p.push(tid);
    message(
        if acknowledged {
            op::LEVEL_SET
        } else {
            op::LEVEL_SET_UNACK
        },
        &p,
    )
}

/// A Generic OnOff or Level Status: present (and target, when moving).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericStatus {
    /// OnOff: present, target.
    OnOff(bool, Option<bool>),
    /// Level: present, target.
    Level(i16, Option<i16>),
}

/// Parses a Generic OnOff or Level Status.
pub fn generic_status(opcode: Opcode, p: &[u8]) -> Option<GenericStatus> {
    match (opcode, p.len()) {
        (op::ONOFF_STATUS, 1) => Some(GenericStatus::OnOff(p[0] == 1, None)),
        (op::ONOFF_STATUS, 3) => Some(GenericStatus::OnOff(p[0] == 1, Some(p[1] == 1))),
        (op::LEVEL_STATUS, 2) => Some(GenericStatus::Level(i16::from_le_bytes([p[0], p[1]]), None)),
        (op::LEVEL_STATUS, 5) => Some(GenericStatus::Level(
            i16::from_le_bytes([p[0], p[1]]),
            Some(i16::from_le_bytes([p[2], p[3]])),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_round_trip_and_name() {
        for opc in [0x00u32, 0x02, 0x8201, 0x804a, 0xc0_5901] {
            let m = message(opc, &[9]);
            assert_eq!(split(&m), Some((opc, &[9u8][..])));
        }
        assert_eq!(split(&[0x7f]), None);
        assert_eq!(split(&[0x82]), None);
        assert_eq!(name(op::ONOFF_SET), Some("Generic OnOff Set"));
        assert_eq!(name(op::APPKEY_ADD), Some("Config AppKey Add"));
        assert_eq!(ModelId::Sig(0x1000).name(), Some("Generic OnOff Server"));
    }

    #[test]
    fn config_messages() {
        assert_eq!(key_indexes(0x123, 0x456), [0x23, 0x61, 0x45]);
        let m = appkey_add(0, 1, &[0xaa; 16]);
        assert_eq!(&m[..4], &[0x00, 0x00, 0x10, 0x00]);
        assert_eq!(m.len(), 20);
        assert_eq!(
            model_app_bind(0x0b0c, 1, ModelId::Sig(0x1000)),
            vec![0x80, 0x3d, 0x0c, 0x0b, 0x01, 0x00, 0x00, 0x10]
        );
    }

    #[test]
    fn composition_data() {
        // CID 0x0059, PID 1, VID 2, CRPL 0x10, features relay+proxy; one
        // element at location 0x0100 with Config Server, Health Server,
        // Generic OnOff Server and one vendor model.
        let p = hex::decode(
            "00 5900 0100 0200 1000 0300 0001 03 01 0000 0200 0010 5900 2a00".replace(' ', ""),
        )
        .unwrap();
        let c = Composition::parse(&p).unwrap();
        assert_eq!((c.cid, c.features), (0x0059, 3));
        assert_eq!(
            c.elements[0].models,
            vec![
                ModelId::Sig(0),
                ModelId::Sig(2),
                ModelId::Sig(0x1000),
                ModelId::Vendor(0x59, 0x2a)
            ]
        );
        assert!(Composition::parse(&p[..p.len() - 1]).is_none());
    }

    #[test]
    fn generic_messages() {
        assert_eq!(onoff_set(true, 7, true), vec![0x82, 0x02, 1, 7]);
        assert_eq!(
            generic_status(op::ONOFF_STATUS, &[1, 0, 5]),
            Some(GenericStatus::OnOff(true, Some(false)))
        );
        assert_eq!(
            generic_status(op::LEVEL_STATUS, &[0xff, 0x7f]),
            Some(GenericStatus::Level(i16::MAX, None))
        );
        assert_eq!(generic_status(op::LEVEL_STATUS, &[1]), None);
    }
}
