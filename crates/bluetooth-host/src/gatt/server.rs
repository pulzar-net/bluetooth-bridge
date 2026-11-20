//! Our GATT server: a database built at run time (services can be added and
//! removed while running), with per-attribute security, client
//! configuration per connection (kept across reconnections for bonded
//! peers), long writes, and the GATT service's Service Changed and
//! Database Hash so clients can cache.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bluetooth_adv::Uuid;
use serde::{Deserialize, Serialize};

use super::{uuid, uuid_bytes, Properties};
use crate::att::{ecode, error_pdu, op};
use crate::connection::{ConnState, Security};
use crate::error::{Error, Result};
use crate::host::{Host, HostEvent};

/// Who may read or write an attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Nobody.
    Never,
    /// Anyone connected.
    #[default]
    Open,
    /// An encrypted link.
    Encrypted,
    /// An encrypted link with an authenticated (MITM-protected) key.
    Authenticated,
    /// Authenticated LE Secure Connections with a 128-bit key.
    SecureConnections,
}

impl Access {
    /// `None` when allowed, else the ATT error to return.
    fn check(self, s: &Security) -> Option<u8> {
        match self {
            Access::Never => Some(0), // replaced by the caller with read/write-not-permitted
            Access::Open => None,
            Access::Encrypted if s.encrypted => None,
            Access::Authenticated if s.encrypted && s.authenticated => None,
            Access::SecureConnections if s.level() == 4 => None,
            // Without encryption the client should pair (or encrypt with its bond).
            _ if !s.encrypted => Some(ecode::INSUFFICIENT_AUTHENTICATION),
            _ if s.key_size < 16 && self == Access::SecureConnections => {
                Some(ecode::KEY_SIZE_TOO_SHORT)
            }
            _ => Some(ecode::INSUFFICIENT_AUTHENTICATION),
        }
    }
}

/// A descriptor to add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DescriptorDef {
    /// Its UUID.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub uuid: Uuid,
    /// Read access.
    #[serde(default)]
    pub read: Access,
    /// Write access.
    #[serde(default = "never")]
    pub write: Access,
    /// The value.
    #[serde(default, with = "hex_bytes")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub value: Vec<u8>,
}

fn never() -> Access {
    Access::Never
}

/// A characteristic to add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CharacteristicDef {
    /// Its UUID.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub uuid: Uuid,
    /// Its properties, by name: `read`, `write`, `write_without_response`,
    /// `notify`, `indicate`, `broadcast`.
    pub properties: Vec<String>,
    /// Read access.
    #[serde(default)]
    pub read: Access,
    /// Write access.
    #[serde(default)]
    pub write: Access,
    /// The initial value.
    #[serde(default, with = "hex_bytes")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub value: Vec<u8>,
    /// The longest value a client may write (at most 512).
    #[serde(default = "max_len")]
    pub max_len: usize,
    /// A Characteristic User Description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Other descriptors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub descriptors: Vec<DescriptorDef>,
}

fn max_len() -> usize {
    512
}

/// A service to add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ServiceDef {
    /// Its UUID.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub uuid: Uuid,
    /// Primary (the default) or secondary.
    #[serde(default = "yes")]
    pub primary: bool,
    /// Its characteristics.
    pub characteristics: Vec<CharacteristicDef>,
}

fn yes() -> bool {
    true
}

mod hex_bytes {
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        hex::decode(s.trim()).map_err(serde::de::Error::custom)
    }
}

/// The handles of an added service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceHandles {
    /// The service declaration.
    pub start: u16,
    /// The last handle.
    pub end: u16,
    /// Each characteristic's value handle, in the order given.
    pub characteristics: Vec<(Uuid, u16)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Service,
    Declaration,
    Value {
        props: Properties,
        max_len: usize,
        cccd: Option<u16>,
    },
    Cccd {
        value: u16,
    },
    Descriptor,
}

#[derive(Debug, Clone)]
struct Attr {
    handle: u16,
    ty: Uuid,
    kind: Kind,
    read: Access,
    write: Access,
    value: Vec<u8>,
    /// The service this attribute belongs to (its declaration's handle).
    service: u16,
}

struct Db {
    attrs: Vec<Attr>,
    /// Client configuration: (connection handle, value handle) -> bits.
    cccd: HashMap<(u16, u16), u16>,
    /// Queued prepared writes, per connection.
    prepared: HashMap<u16, Vec<(u16, u16, Vec<u8>)>>,
    service_changed: u16,
    hash_handle: u16,
}

/// The server's attribute database.
pub struct Database {
    db: Mutex<Db>,
}

/// Prepared writes a client may queue before executing.
const MAX_PREPARED: usize = 64;

impl Database {
    pub(crate) fn new(name: &str, appearance: u16) -> Self {
        let d = Database {
            db: Mutex::new(Db {
                attrs: Vec::new(),
                cccd: HashMap::new(),
                prepared: HashMap::new(),
                service_changed: 0,
                hash_handle: 0,
            }),
        };
        let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        d.add(&ServiceDef {
            uuid: Uuid::Uuid16(uuid::GAP),
            primary: true,
            characteristics: vec![
                CharacteristicDef {
                    uuid: Uuid::Uuid16(uuid::DEVICE_NAME),
                    properties: p(&["read"]),
                    read: Access::Open,
                    write: Access::Never,
                    value: name.as_bytes().to_vec(),
                    max_len: 248,
                    description: None,
                    descriptors: vec![],
                },
                CharacteristicDef {
                    uuid: Uuid::Uuid16(uuid::APPEARANCE),
                    properties: p(&["read"]),
                    read: Access::Open,
                    write: Access::Never,
                    value: appearance.to_le_bytes().to_vec(),
                    max_len: 2,
                    description: None,
                    descriptors: vec![],
                },
                // We resolve private addresses, so a peer may direct to our RPA.
                CharacteristicDef {
                    uuid: Uuid::Uuid16(uuid::CENTRAL_ADDRESS_RESOLUTION),
                    properties: p(&["read"]),
                    read: Access::Open,
                    write: Access::Never,
                    value: vec![1],
                    max_len: 1,
                    description: None,
                    descriptors: vec![],
                },
            ],
        })
        .expect("the GAP service fits");
        let gatt = d
            .add(&ServiceDef {
                uuid: Uuid::Uuid16(uuid::GATT),
                primary: true,
                characteristics: vec![
                    CharacteristicDef {
                        uuid: Uuid::Uuid16(uuid::SERVICE_CHANGED),
                        properties: p(&["indicate"]),
                        read: Access::Never,
                        write: Access::Never,
                        value: vec![0; 4],
                        max_len: 4,
                        description: None,
                        descriptors: vec![],
                    },
                    CharacteristicDef {
                        uuid: Uuid::Uuid16(uuid::CLIENT_SUPPORTED_FEATURES),
                        properties: p(&["read", "write"]),
                        read: Access::Open,
                        write: Access::Open,
                        value: vec![0],
                        max_len: 1,
                        description: None,
                        descriptors: vec![],
                    },
                    CharacteristicDef {
                        uuid: Uuid::Uuid16(uuid::DATABASE_HASH),
                        properties: p(&["read"]),
                        read: Access::Open,
                        write: Access::Never,
                        value: vec![0; 16],
                        max_len: 16,
                        description: None,
                        descriptors: vec![],
                    },
                ],
            })
            .expect("the GATT service fits");
        {
            let mut db = d.lock();
            db.service_changed = gatt.characteristics[0].1;
            db.hash_handle = gatt.characteristics[2].1;
            update_hash(&mut db);
        }
        d
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Db> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds a service at the end of the database.
    pub fn add(&self, s: &ServiceDef) -> Result<ServiceHandles> {
        let mut db = self.lock();
        let mut next = db.attrs.last().map(|a| a.handle + 1).unwrap_or(1);
        let needed = 1 + s
            .characteristics
            .iter()
            .map(|c| {
                let p = Properties::from_names(&c.properties).unwrap_or_default();
                2 + usize::from(p.has(Properties::NOTIFY) || p.has(Properties::INDICATE))
                    + usize::from(c.description.is_some())
                    + c.descriptors.len()
            })
            .sum::<usize>();
        if usize::from(next) + needed > 0xffff {
            return Err(Error::InvalidParameter("the GATT database is full".into()));
        }
        let start = next;
        let mut new = Vec::with_capacity(needed);
        new.push(Attr {
            handle: next,
            ty: Uuid::Uuid16(if s.primary {
                uuid::PRIMARY_SERVICE
            } else {
                uuid::SECONDARY_SERVICE
            }),
            kind: Kind::Service,
            read: Access::Open,
            write: Access::Never,
            value: uuid_bytes(&s.uuid),
            service: start,
        });
        next += 1;
        let mut chars = Vec::new();
        for c in &s.characteristics {
            let props = Properties::from_names(&c.properties).map_err(Error::InvalidParameter)?;
            if c.max_len > 512 || c.value.len() > c.max_len {
                return Err(Error::InvalidParameter(format!(
                    "characteristic {} value over {} octets",
                    c.uuid, c.max_len
                )));
            }
            let decl = next;
            let value_handle = next + 1;
            let mut dv = vec![props.0];
            dv.extend_from_slice(&value_handle.to_le_bytes());
            dv.extend_from_slice(&uuid_bytes(&c.uuid));
            new.push(Attr {
                handle: decl,
                ty: Uuid::Uuid16(uuid::CHARACTERISTIC),
                kind: Kind::Declaration,
                read: Access::Open,
                write: Access::Never,
                value: dv,
                service: start,
            });
            let notifies = props.has(Properties::NOTIFY) || props.has(Properties::INDICATE);
            let read = if props.has(Properties::READ) {
                c.read
            } else {
                Access::Never
            };
            let write =
                if props.has(Properties::WRITE) || props.has(Properties::WRITE_WITHOUT_RESPONSE) {
                    c.write
                } else {
                    Access::Never
                };
            next += 2;
            let cccd = notifies.then_some(next);
            new.push(Attr {
                handle: value_handle,
                ty: c.uuid,
                kind: Kind::Value {
                    props,
                    max_len: c.max_len,
                    cccd,
                },
                read,
                write,
                value: c.value.clone(),
                service: start,
            });
            if let Some(h) = cccd {
                new.push(Attr {
                    handle: h,
                    ty: Uuid::Uuid16(uuid::CCCD),
                    kind: Kind::Cccd {
                        value: value_handle,
                    },
                    read: Access::Open,
                    write: c.read.max_open(),
                    value: vec![0, 0],
                    service: start,
                });
                next += 1;
            }
            if let Some(d) = &c.description {
                new.push(Attr {
                    handle: next,
                    ty: Uuid::Uuid16(uuid::USER_DESCRIPTION),
                    kind: Kind::Descriptor,
                    read: Access::Open,
                    write: Access::Never,
                    value: d.as_bytes().to_vec(),
                    service: start,
                });
                next += 1;
            }
            for d in &c.descriptors {
                new.push(Attr {
                    handle: next,
                    ty: d.uuid,
                    kind: Kind::Descriptor,
                    read: d.read,
                    write: d.write,
                    value: d.value.clone(),
                    service: start,
                });
                next += 1;
            }
            chars.push((c.uuid, value_handle));
        }
        let end = next - 1;
        db.attrs.extend(new);
        update_hash(&mut db);
        Ok(ServiceHandles {
            start,
            end,
            characteristics: chars,
        })
    }

    /// Removes the service whose declaration is at `start`; returns the
    /// range it held (for Service Changed).
    pub fn remove(&self, start: u16) -> Result<(u16, u16)> {
        let mut db = self.lock();
        let range: Vec<u16> = db
            .attrs
            .iter()
            .filter(|a| a.service == start)
            .map(|a| a.handle)
            .collect();
        let (Some(&first), Some(&last)) = (range.first(), range.last()) else {
            return Err(Error::InvalidParameter(format!(
                "no service at handle {start:#06x}"
            )));
        };
        if db
            .attrs
            .iter()
            .any(|a| a.handle == first && a.ty == Uuid::Uuid16(uuid::GATT))
            || first <= db.hash_handle
        {
            return Err(Error::InvalidParameter(
                "the GAP and GATT services stay".into(),
            ));
        }
        db.attrs.retain(|a| a.service != start);
        db.cccd.retain(|(_, h), _| *h < first || *h > last);
        update_hash(&mut db);
        Ok((first, last))
    }

    /// A value.
    pub fn value(&self, handle: u16) -> Option<Vec<u8>> {
        self.lock()
            .attrs
            .iter()
            .find(|a| a.handle == handle)
            .map(|a| a.value.clone())
    }

    /// Sets a value (no notification).
    pub fn set_value(&self, handle: u16, value: &[u8]) -> Result<()> {
        let mut db = self.lock();
        let a = db
            .attrs
            .iter_mut()
            .find(|a| a.handle == handle)
            .ok_or_else(|| Error::InvalidParameter(format!("no attribute {handle:#06x}")))?;
        if let Kind::Value { max_len, .. } = a.kind {
            if value.len() > max_len {
                return Err(Error::InvalidParameter(format!(
                    "value over {max_len} octets"
                )));
            }
        }
        a.value = value.to_vec();
        Ok(())
    }

    /// Which connections subscribed to a value: (connection, notify, indicate).
    pub(crate) fn subscribers(&self, value_handle: u16) -> Vec<(u16, bool, bool)> {
        self.lock()
            .cccd
            .iter()
            .filter(|((_, h), _)| *h == value_handle)
            .map(|((c, _), bits)| (*c, bits & 1 != 0, bits & 2 != 0))
            .collect()
    }

    /// A connection closed: forget its configuration and queued writes.
    /// Returns its configuration for storing with a bond.
    pub(crate) fn connection_closed(&self, conn: u16) -> Vec<(u16, u16)> {
        let mut db = self.lock();
        db.prepared.remove(&conn);
        let mine: Vec<(u16, u16)> = db
            .cccd
            .iter()
            .filter(|((c, _), _)| *c == conn)
            .map(|((_, h), v)| (*h, *v))
            .collect();
        db.cccd.retain(|(c, _), _| *c != conn);
        mine
    }

    /// A connection's current client configuration: (value handle, bits).
    pub(crate) fn subscriptions_of(&self, conn: u16) -> Vec<(u16, u16)> {
        self.lock()
            .cccd
            .iter()
            .filter(|((c, _), _)| *c == conn)
            .map(|((_, h), v)| (*h, *v))
            .collect()
    }

    /// Restores a bonded client's configuration on a new connection.
    pub(crate) fn restore(&self, conn: u16, cccds: &[(u16, u16)]) {
        let mut db = self.lock();
        for (h, v) in cccds {
            if db
                .attrs
                .iter()
                .any(|a| a.handle == *h && matches!(a.kind, Kind::Value { cccd: Some(_), .. }))
            {
                db.cccd.insert((conn, *h), *v);
            }
        }
    }

    /// The Service Changed characteristic's value handle.
    pub(crate) fn service_changed_handle(&self) -> u16 {
        self.lock().service_changed
    }

    /// Runs a request without a connection (the fuzz targets).
    #[cfg(feature = "fuzzing")]
    pub(crate) fn handle_fuzz(
        &self,
        conn: u16,
        sec: &Security,
        mtu: usize,
        pdu: &[u8],
    ) -> Option<Vec<u8>> {
        let mut events = Vec::new();
        let mut db = self.lock();
        match handle_locked(&mut db, conn, sec, mtu, pdu, &mut events) {
            Ok(r) => r,
            Err((h, code)) => Some(error_pdu(pdu[0], h, code)),
        }
    }

    /// Handles an ATT request or command; returns the response to send.
    pub(crate) async fn handle(
        &self,
        host: &Host,
        conn: &Arc<ConnState>,
        pdu: &[u8],
    ) -> Option<Vec<u8>> {
        let sec = *conn.security.borrow();
        let mtu = usize::from(conn.att.mtu());
        let opcode = pdu[0];
        let mut events = Vec::new();
        let rsp = {
            let mut db = self.lock();
            match handle_locked(&mut db, conn.handle, &sec, mtu, pdu, &mut events) {
                Ok(r) => r,
                Err((h, code)) => Some(error_pdu(opcode, h, code)),
            }
        };
        for e in events {
            host.emit(e);
        }
        // Commands get no answer; neither does anything we cannot parse as a request.
        if opcode & 0x40 != 0 {
            return None;
        }
        rsp
    }
}

trait MaxOpen {
    fn max_open(self) -> Access;
}

impl MaxOpen for Access {
    /// The CCCD is writable by anyone who could read the value.
    fn max_open(self) -> Access {
        match self {
            Access::Never => Access::Open,
            a => a,
        }
    }
}

type Failure = (u16, u8);

fn le16(b: &[u8], i: usize) -> Result<u16, Failure> {
    b.get(i..i + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or((0, ecode::INVALID_PDU))
}

fn range(pdu: &[u8]) -> Result<(u16, u16), Failure> {
    let (s, e) = (le16(pdu, 1)?, le16(pdu, 3)?);
    if s == 0 || s > e {
        return Err((s, ecode::INVALID_HANDLE));
    }
    Ok((s, e))
}

fn group_end(db: &Db, service: u16) -> u16 {
    db.attrs
        .iter()
        .filter(|a| a.service == service)
        .map(|a| a.handle)
        .max()
        .unwrap_or(service)
}

fn readable(a: &Attr, sec: &Security) -> Result<(), Failure> {
    match a.read.check(sec) {
        None => Ok(()),
        Some(0) => Err((a.handle, ecode::READ_NOT_PERMITTED)),
        Some(c) => Err((a.handle, c)),
    }
}

fn writable(a: &Attr, sec: &Security) -> Result<(), Failure> {
    match a.write.check(sec) {
        None => Ok(()),
        Some(0) => Err((a.handle, ecode::WRITE_NOT_PERMITTED)),
        Some(c) => Err((a.handle, c)),
    }
}

/// The value a read returns: the CCCD is per connection.
fn read_value(db: &Db, conn: u16, a: &Attr) -> Vec<u8> {
    match a.kind {
        Kind::Cccd { value } => db
            .cccd
            .get(&(conn, value))
            .copied()
            .unwrap_or(0)
            .to_le_bytes()
            .to_vec(),
        _ => a.value.clone(),
    }
}

fn handle_locked(
    db: &mut Db,
    conn: u16,
    sec: &Security,
    mtu: usize,
    pdu: &[u8],
    events: &mut Vec<HostEvent>,
) -> Result<Option<Vec<u8>>, Failure> {
    let opcode = pdu[0];
    match opcode {
        op::READ_BY_GROUP_REQ => {
            let (s, e) = range(pdu)?;
            let ty = Uuid::from_le_bytes(&pdu[5..]).ok_or((0, ecode::INVALID_PDU))?;
            if ty != Uuid::Uuid16(uuid::PRIMARY_SERVICE)
                && ty != Uuid::Uuid16(uuid::SECONDARY_SERVICE)
            {
                return Err((s, ecode::UNSUPPORTED_GROUP_TYPE));
            }
            let mut out = vec![op::READ_BY_GROUP_RSP, 0];
            let mut len = 0usize;
            for a in db
                .attrs
                .iter()
                .filter(|a| a.handle >= s && a.handle <= e && a.ty == ty)
            {
                let entry_len = 4 + a.value.len();
                if len == 0 {
                    len = entry_len;
                } else if entry_len != len || out.len() + entry_len > mtu {
                    break;
                }
                out.extend_from_slice(&a.handle.to_le_bytes());
                out.extend_from_slice(&group_end(db, a.service).to_le_bytes());
                out.extend_from_slice(&a.value);
            }
            if len == 0 {
                return Err((s, ecode::ATTRIBUTE_NOT_FOUND));
            }
            out[1] = len as u8;
            Ok(Some(out))
        }
        op::FIND_INFO_REQ => {
            let (s, e) = range(pdu)?;
            let mut out = vec![op::FIND_INFO_RSP, 0];
            for a in db.attrs.iter().filter(|a| a.handle >= s && a.handle <= e) {
                let short = a.ty.as_u16().is_some();
                let format = if short { 1 } else { 2 };
                if out[1] == 0 {
                    out[1] = format;
                } else if out[1] != format {
                    break;
                }
                let b = uuid_bytes(&a.ty);
                if out.len() + 2 + b.len() > mtu {
                    break;
                }
                out.extend_from_slice(&a.handle.to_le_bytes());
                out.extend_from_slice(&b);
            }
            if out[1] == 0 {
                return Err((s, ecode::ATTRIBUTE_NOT_FOUND));
            }
            Ok(Some(out))
        }
        op::FIND_BY_TYPE_REQ => {
            let (s, e) = range(pdu)?;
            let ty = Uuid::Uuid16(le16(pdu, 5)?);
            let value = &pdu[7..];
            let mut out = vec![op::FIND_BY_TYPE_RSP];
            for a in db
                .attrs
                .iter()
                .filter(|a| a.handle >= s && a.handle <= e && a.ty == ty && a.value == value)
            {
                if out.len() + 4 > mtu {
                    break;
                }
                let end = if a.kind == Kind::Service {
                    group_end(db, a.service)
                } else {
                    a.handle
                };
                out.extend_from_slice(&a.handle.to_le_bytes());
                out.extend_from_slice(&end.to_le_bytes());
            }
            if out.len() == 1 {
                return Err((s, ecode::ATTRIBUTE_NOT_FOUND));
            }
            Ok(Some(out))
        }
        op::READ_BY_TYPE_REQ => {
            let (s, e) = range(pdu)?;
            let ty = Uuid::from_le_bytes(&pdu[5..]).ok_or((0, ecode::INVALID_PDU))?;
            let mut out = vec![op::READ_BY_TYPE_RSP, 0];
            let mut len = 0usize;
            for a in db
                .attrs
                .iter()
                .filter(|a| a.handle >= s && a.handle <= e && a.ty == ty)
            {
                if let Err(f) = readable(a, sec) {
                    if len == 0 {
                        return Err(f);
                    }
                    break;
                }
                let v = read_value(db, conn, a);
                let v = &v[..v.len().min(mtu - 4).min(253)];
                let entry = 2 + v.len();
                if len == 0 {
                    len = entry;
                } else if entry != len || out.len() + entry > mtu {
                    break;
                }
                out.extend_from_slice(&a.handle.to_le_bytes());
                out.extend_from_slice(v);
            }
            if len == 0 {
                return Err((s, ecode::ATTRIBUTE_NOT_FOUND));
            }
            out[1] = len as u8;
            Ok(Some(out))
        }
        op::READ_REQ | op::READ_BLOB_REQ => {
            let h = le16(pdu, 1)?;
            let offset = if opcode == op::READ_BLOB_REQ {
                usize::from(le16(pdu, 3)?)
            } else {
                0
            };
            let a = db
                .attrs
                .iter()
                .find(|a| a.handle == h)
                .ok_or((h, ecode::INVALID_HANDLE))?;
            readable(a, sec)?;
            let v = read_value(db, conn, a);
            if offset > v.len() {
                return Err((h, ecode::INVALID_OFFSET));
            }
            let mut out = vec![opcode + 1];
            let part = &v[offset..];
            out.extend_from_slice(&part[..part.len().min(mtu - 1)]);
            Ok(Some(out))
        }
        op::READ_MULTIPLE_REQ | op::READ_MULTIPLE_VAR_REQ => {
            let mut out = vec![opcode + 1];
            for c in pdu[1..].chunks_exact(2) {
                let h = u16::from_le_bytes([c[0], c[1]]);
                let a = db
                    .attrs
                    .iter()
                    .find(|a| a.handle == h)
                    .ok_or((h, ecode::INVALID_HANDLE))?;
                readable(a, sec)?;
                let v = read_value(db, conn, a);
                if opcode == op::READ_MULTIPLE_VAR_REQ {
                    out.extend_from_slice(&(v.len() as u16).to_le_bytes());
                }
                out.extend_from_slice(&v);
            }
            out.truncate(mtu);
            Ok(Some(out))
        }
        op::WRITE_REQ | op::WRITE_CMD => {
            let h = le16(pdu, 1)?;
            let value = pdu[3..].to_vec();
            write_value(db, conn, sec, h, 0, value, opcode == op::WRITE_CMD, events)?;
            Ok((opcode == op::WRITE_REQ).then(|| vec![op::WRITE_RSP]))
        }
        op::PREPARE_WRITE_REQ => {
            let (h, offset) = (le16(pdu, 1)?, le16(pdu, 3)?);
            let a = db
                .attrs
                .iter()
                .find(|a| a.handle == h)
                .ok_or((h, ecode::INVALID_HANDLE))?;
            writable(a, sec)?;
            let q = db.prepared.entry(conn).or_default();
            if q.len() >= MAX_PREPARED {
                return Err((h, ecode::PREPARE_QUEUE_FULL));
            }
            q.push((h, offset, pdu[5..].to_vec()));
            let mut out = pdu.to_vec();
            out[0] = op::PREPARE_WRITE_RSP;
            Ok(Some(out))
        }
        op::EXECUTE_WRITE_REQ => {
            let flags = *pdu.get(1).ok_or((0, ecode::INVALID_PDU))?;
            let queue = db.prepared.remove(&conn).unwrap_or_default();
            if flags == 0x01 {
                // Assemble each handle's value from its parts, in order.
                let mut values: Vec<(u16, Vec<u8>)> = Vec::new();
                for (h, offset, part) in queue {
                    let i = match values.iter().position(|(x, _)| *x == h) {
                        Some(i) => i,
                        None => {
                            let cur = db
                                .attrs
                                .iter()
                                .find(|a| a.handle == h)
                                .map(|a| a.value.clone())
                                .unwrap_or_default();
                            values.push((h, cur));
                            values.len() - 1
                        }
                    };
                    let v = &mut values[i].1;
                    let offset = usize::from(offset);
                    if offset > v.len() {
                        return Err((h, ecode::INVALID_OFFSET));
                    }
                    v.truncate(offset);
                    v.extend_from_slice(&part);
                }
                for (h, v) in values {
                    write_value(db, conn, sec, h, 0, v, false, events)?;
                }
            }
            Ok(Some(vec![op::EXECUTE_WRITE_RSP]))
        }
        op::SIGNED_WRITE_CMD => {
            // Signed writes need the peer's CSRK and sign counter; not taken.
            Ok(None)
        }
        _ => Err((0, ecode::REQUEST_NOT_SUPPORTED)),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_value(
    db: &mut Db,
    conn: u16,
    sec: &Security,
    h: u16,
    _offset: usize,
    value: Vec<u8>,
    command: bool,
    events: &mut Vec<HostEvent>,
) -> Result<(), Failure> {
    let a = db
        .attrs
        .iter()
        .find(|a| a.handle == h)
        .ok_or((h, ecode::INVALID_HANDLE))?;
    writable(a, sec)?;
    match a.kind {
        Kind::Cccd { value: vh } => {
            if value.len() != 2 {
                return Err((h, ecode::INVALID_LENGTH));
            }
            let bits = u16::from_le_bytes([value[0], value[1]]);
            let props = db
                .attrs
                .iter()
                .find(|x| x.handle == vh)
                .and_then(|x| match x.kind {
                    Kind::Value { props, .. } => Some(props),
                    _ => None,
                })
                .unwrap_or_default();
            if bits & !3 != 0
                || (bits & 1 != 0 && !props.has(Properties::NOTIFY))
                || (bits & 2 != 0 && !props.has(Properties::INDICATE))
            {
                return Err((h, ecode::CCCD_IMPROPER));
            }
            if bits == 0 {
                db.cccd.remove(&(conn, vh));
            } else {
                db.cccd.insert((conn, vh), bits);
            }
            events.push(HostEvent::GattSubscription {
                handle: conn,
                attribute: vh,
                notify: bits & 1 != 0,
                indicate: bits & 2 != 0,
            });
        }
        Kind::Value { props, max_len, .. } => {
            let allowed = if command {
                props.has(Properties::WRITE_WITHOUT_RESPONSE)
            } else {
                props.has(Properties::WRITE)
            };
            if !allowed {
                return Err((h, ecode::WRITE_NOT_PERMITTED));
            }
            if value.len() > max_len {
                return Err((h, ecode::INVALID_LENGTH));
            }
            let a = db
                .attrs
                .iter_mut()
                .find(|a| a.handle == h)
                .ok_or((h, ecode::INVALID_HANDLE))?;
            a.value = value.clone();
            events.push(HostEvent::GattWrite {
                handle: conn,
                attribute: h,
                value,
            });
        }
        Kind::Descriptor => {
            let a = db
                .attrs
                .iter_mut()
                .find(|a| a.handle == h)
                .ok_or((h, ecode::INVALID_HANDLE))?;
            a.value = value.clone();
            events.push(HostEvent::GattWrite {
                handle: conn,
                attribute: h,
                value,
            });
        }
        _ => return Err((h, ecode::WRITE_NOT_PERMITTED)),
    }
    Ok(())
}

/// The Database Hash (Core Vol 3, Part G, 7.3): AES-CMAC with a zero key
/// over the handle, type and (for declarations and Extended Properties)
/// value of the declarations and descriptors that shape the database.
fn update_hash(db: &mut Db) {
    let mut m = Vec::new();
    for a in &db.attrs {
        let Some(t) = a.ty.as_u16() else { continue };
        let with_value = matches!(
            t,
            uuid::PRIMARY_SERVICE
                | uuid::SECONDARY_SERVICE
                | uuid::INCLUDE
                | uuid::CHARACTERISTIC
                | uuid::EXTENDED_PROPERTIES
        );
        let without = matches!(
            t,
            uuid::USER_DESCRIPTION
                | uuid::CCCD
                | uuid::SCCD
                | uuid::PRESENTATION_FORMAT
                | uuid::AGGREGATE_FORMAT
        );
        if with_value || without {
            m.extend_from_slice(&a.handle.to_le_bytes());
            m.extend_from_slice(&t.to_le_bytes());
            if with_value {
                m.extend_from_slice(&a.value);
            }
        }
    }
    let hash = {
        use cmac::Mac;
        let mut mac = <cmac::Cmac<aes::Aes128> as aes::cipher::KeyInit>::new(&[0u8; 16].into());
        mac.update(&m);
        let h: [u8; 16] = mac.finalize().into_bytes().into();
        h
    };
    let hh = db.hash_handle;
    if let Some(a) = db.attrs.iter_mut().find(|a| a.handle == hh && hh != 0) {
        // Sent least significant octet first.
        a.value = hash.iter().rev().copied().collect();
    }
}

/// The application's handle on the GATT server.
#[derive(Clone)]
pub struct Server {
    pub(crate) host: Host,
}

impl Server {
    /// Adds a service; connected clients are told with Service Changed.
    pub async fn add(&self, s: &ServiceDef) -> Result<ServiceHandles> {
        let h = self.host.inner.gatt.add(s)?;
        self.service_changed(h.start, h.end).await;
        Ok(h)
    }

    /// Removes the service declared at `start`.
    pub async fn remove(&self, start: u16) -> Result<()> {
        let (a, b) = self.host.inner.gatt.remove(start)?;
        self.service_changed(a, b).await;
        Ok(())
    }

    async fn service_changed(&self, start: u16, end: u16) {
        let db = &self.host.inner.gatt;
        let sc = db.service_changed_handle();
        let mut v = start.to_le_bytes().to_vec();
        v.extend_from_slice(&end.to_le_bytes());
        for (conn, _, indicate) in db.subscribers(sc) {
            if indicate {
                if let Some(c) = self.host.state(conn) {
                    let _ = c.att.indicate(&self.host, &c, sc, &v).await;
                }
            }
        }
    }

    /// A value.
    pub fn value(&self, handle: u16) -> Option<Vec<u8>> {
        self.host.inner.gatt.value(handle)
    }

    /// Sets a value without telling anyone.
    pub fn set(&self, handle: u16, value: &[u8]) -> Result<()> {
        self.host.inner.gatt.set_value(handle, value)
    }

    /// Sets a value and notifies (or indicates) every subscribed client.
    /// Returns how many clients were told.
    pub async fn notify(&self, handle: u16, value: &[u8]) -> Result<usize> {
        self.set(handle, value)?;
        let mut n = 0;
        for (conn, notify, indicate) in self.host.inner.gatt.subscribers(handle) {
            let Some(c) = self.host.state(conn) else {
                continue;
            };
            let r = if indicate {
                c.att.indicate(&self.host, &c, handle, value).await
            } else if notify {
                c.att.notify(&self.host, &c, handle, value).await
            } else {
                continue;
            };
            match r {
                Ok(()) => n += 1,
                Err(e) => tracing::debug!("could not update {conn:#05x}: {e}"),
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec() -> Security {
        Security::default()
    }

    #[test]
    fn database_layout_and_requests() {
        let db = Database::new("test", 0);
        let h = db
            .add(&ServiceDef {
                uuid: Uuid::Uuid16(0x180f),
                primary: true,
                characteristics: vec![CharacteristicDef {
                    uuid: Uuid::Uuid16(0x2a19),
                    properties: vec!["read".into(), "notify".into()],
                    read: Access::Open,
                    write: Access::Never,
                    value: vec![99],
                    max_len: 1,
                    description: Some("Battery".into()),
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let vh = h.characteristics[0].1;
        let mut d = db.lock();
        let mut ev = Vec::new();
        // Discover primary services.
        let r = handle_locked(
            &mut d,
            1,
            &sec(),
            23,
            &[0x10, 1, 0, 0xff, 0xff, 0x00, 0x28],
            &mut ev,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r[0], op::READ_BY_GROUP_RSP);
        assert_eq!(r[1], 6);
        // Read the battery level.
        let v = vh.to_le_bytes();
        let r = handle_locked(&mut d, 1, &sec(), 23, &[0x0a, v[0], v[1]], &mut ev)
            .unwrap()
            .unwrap();
        assert_eq!(r, vec![op::READ_RSP, 99]);
        // Writing it is not permitted.
        let e = handle_locked(&mut d, 1, &sec(), 23, &[0x12, v[0], v[1], 1], &mut ev).unwrap_err();
        assert_eq!(e.1, ecode::WRITE_NOT_PERMITTED);
        // Subscribe, then indications are refused (notify only).
        let c = (vh + 1).to_le_bytes();
        handle_locked(&mut d, 1, &sec(), 23, &[0x12, c[0], c[1], 1, 0], &mut ev).unwrap();
        let e =
            handle_locked(&mut d, 1, &sec(), 23, &[0x12, c[0], c[1], 2, 0], &mut ev).unwrap_err();
        assert_eq!(e.1, ecode::CCCD_IMPROPER);
        drop(d);
        assert_eq!(db.subscribers(vh), vec![(1, true, false)]);
        assert!(matches!(
            ev[0],
            HostEvent::GattSubscription { notify: true, .. }
        ));
        assert_eq!(db.connection_closed(1), vec![(vh, 1)]);
        assert!(db.subscribers(vh).is_empty());
    }

    #[test]
    fn security_is_enforced() {
        let db = Database::new("t", 0);
        let h = db
            .add(&ServiceDef {
                uuid: Uuid::parse("12345678-1234-5678-1234-56789abcdef0").unwrap(),
                primary: true,
                characteristics: vec![CharacteristicDef {
                    uuid: Uuid::Uuid16(0x2a00),
                    properties: vec!["read".into(), "write".into()],
                    read: Access::Encrypted,
                    write: Access::Authenticated,
                    value: vec![1],
                    max_len: 4,
                    description: None,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let v = h.characteristics[0].1.to_le_bytes();
        let mut d = db.lock();
        let mut ev = Vec::new();
        let e = handle_locked(&mut d, 1, &sec(), 23, &[0x0a, v[0], v[1]], &mut ev).unwrap_err();
        assert_eq!(e.1, ecode::INSUFFICIENT_AUTHENTICATION);
        let enc = Security {
            encrypted: true,
            key_size: 16,
            ..Security::default()
        };
        assert!(handle_locked(&mut d, 1, &enc, 23, &[0x0a, v[0], v[1]], &mut ev).is_ok());
        let e = handle_locked(&mut d, 1, &enc, 23, &[0x12, v[0], v[1], 7], &mut ev).unwrap_err();
        assert_eq!(e.1, ecode::INSUFFICIENT_AUTHENTICATION);
        let auth = Security {
            authenticated: true,
            ..enc
        };
        assert!(handle_locked(&mut d, 1, &auth, 23, &[0x12, v[0], v[1], 7], &mut ev).is_ok());
        let e = handle_locked(
            &mut d,
            1,
            &auth,
            23,
            &[0x12, v[0], v[1], 1, 2, 3, 4, 5],
            &mut ev,
        )
        .unwrap_err();
        assert_eq!(e.1, ecode::INVALID_LENGTH);
    }

    #[test]
    fn long_write_assembles_parts() {
        let db = Database::new("t", 0);
        let h = db
            .add(&ServiceDef {
                uuid: Uuid::Uuid16(0xfff0),
                primary: true,
                characteristics: vec![CharacteristicDef {
                    uuid: Uuid::Uuid16(0xfff1),
                    properties: vec!["read".into(), "write".into()],
                    read: Access::Open,
                    write: Access::Open,
                    value: vec![],
                    max_len: 512,
                    description: None,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let v = h.characteristics[0].1.to_le_bytes();
        let mut d = db.lock();
        let mut ev = Vec::new();
        handle_locked(
            &mut d,
            1,
            &sec(),
            23,
            &[0x16, v[0], v[1], 0, 0, 1, 2, 3],
            &mut ev,
        )
        .unwrap();
        handle_locked(
            &mut d,
            1,
            &sec(),
            23,
            &[0x16, v[0], v[1], 3, 0, 4, 5],
            &mut ev,
        )
        .unwrap();
        handle_locked(&mut d, 1, &sec(), 23, &[0x18, 0x01], &mut ev).unwrap();
        drop(d);
        assert_eq!(db.value(h.characteristics[0].1), Some(vec![1, 2, 3, 4, 5]));
    }
}
