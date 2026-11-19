//! The GATT client: discovery, reads, writes and subscriptions on a peer's
//! server (Core Vol 3, Part G, 4).

use bluetooth_adv::Uuid;

use super::{uuid, Characteristic, Descriptor, Properties, Service};
use crate::att::{ecode, op};
use crate::connection::Connection;
use crate::error::{Error, Result};

/// The GATT client of one connection.
#[derive(Clone)]
pub struct Client {
    pub(crate) conn: Connection,
}

fn le16(b: &[u8], i: usize) -> Result<u16> {
    b.get(i..i + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| Error::Protocol("short ATT response".into()))
}

fn not_found(e: &Error) -> bool {
    matches!(e, Error::Att { code, .. } if *code == ecode::ATTRIBUTE_NOT_FOUND)
}

impl Client {
    async fn request(&self, pdu: Vec<u8>) -> Result<Vec<u8>> {
        let c = &self.conn;
        c.state.att.request(&c.host, &c.state, pdu).await
    }

    fn mtu(&self) -> usize {
        usize::from(self.conn.state.att.mtu())
    }

    /// Exchanges the ATT MTU, offering `mtu` (23 to 517); returns the one in use.
    pub async fn exchange_mtu(&self, mtu: u16) -> Result<u16> {
        let c = &self.conn;
        c.state.att.exchange_mtu(&c.host, &c.state, mtu).await
    }

    /// Every primary service.
    pub async fn services(&self) -> Result<Vec<Service>> {
        let mut out = Vec::new();
        let mut start = 0x0001u16;
        loop {
            let mut pdu = vec![op::READ_BY_GROUP_REQ];
            pdu.extend_from_slice(&start.to_le_bytes());
            pdu.extend_from_slice(&0xffffu16.to_le_bytes());
            pdu.extend_from_slice(&uuid::PRIMARY_SERVICE.to_le_bytes());
            let rsp = match self.request(pdu).await {
                Ok(r) => r,
                Err(e) if not_found(&e) => break,
                Err(e) => return Err(e),
            };
            let len = usize::from(
                *rsp.get(1)
                    .ok_or_else(|| Error::Protocol("empty response".into()))?,
            );
            if len != 6 && len != 20 {
                return Err(Error::Protocol(format!(
                    "Read By Group Type entry length {len}"
                )));
            }
            let mut last = start;
            for e in rsp[2..].chunks_exact(len) {
                let (s, end) = (le16(e, 0)?, le16(e, 2)?);
                let u = Uuid::from_le_bytes(&e[4..])
                    .ok_or_else(|| Error::Protocol("bad service UUID".into()))?;
                out.push(Service {
                    uuid: u,
                    name: u.name(),
                    primary: true,
                    start: s,
                    end,
                    characteristics: Vec::new(),
                });
                last = end;
            }
            if last == 0xffff || last < start {
                break;
            }
            start = last + 1;
        }
        Ok(out)
    }

    /// Primary services with one UUID.
    pub async fn services_by_uuid(&self, service: Uuid) -> Result<Vec<Service>> {
        let mut out = Vec::new();
        let mut start = 0x0001u16;
        loop {
            let mut pdu = vec![op::FIND_BY_TYPE_REQ];
            pdu.extend_from_slice(&start.to_le_bytes());
            pdu.extend_from_slice(&0xffffu16.to_le_bytes());
            pdu.extend_from_slice(&uuid::PRIMARY_SERVICE.to_le_bytes());
            pdu.extend_from_slice(&super::uuid_bytes(&service));
            let rsp = match self.request(pdu).await {
                Ok(r) => r,
                Err(e) if not_found(&e) => break,
                Err(e) => return Err(e),
            };
            let mut last = start;
            for e in rsp[1..].chunks_exact(4) {
                let (s, end) = (le16(e, 0)?, le16(e, 2)?);
                out.push(Service {
                    uuid: service,
                    name: service.name(),
                    primary: true,
                    start: s,
                    end,
                    characteristics: Vec::new(),
                });
                last = end;
            }
            if last == 0xffff || last < start {
                break;
            }
            start = last + 1;
        }
        Ok(out)
    }

    /// The services a service includes: (include declaration handle, service).
    pub async fn included(&self, service: &Service) -> Result<Vec<(u16, Service)>> {
        let found = self
            .read_by_type_all(service.start, service.end, Uuid::Uuid16(uuid::INCLUDE))
            .await?;
        let mut out = Vec::new();
        for (h, v) in found {
            let (s, end) = (le16(&v, 0)?, le16(&v, 2)?);
            let u = match v.len() {
                6 => Uuid::Uuid16(le16(&v, 4)?),
                // A 128-bit service UUID is not in the declaration; read it.
                _ => Uuid::from_le_bytes(&self.read(s).await?)
                    .ok_or_else(|| Error::Protocol("bad included UUID".into()))?,
            };
            out.push((
                h,
                Service {
                    uuid: u,
                    name: u.name(),
                    primary: false,
                    start: s,
                    end,
                    characteristics: Vec::new(),
                },
            ));
        }
        Ok(out)
    }

    /// The characteristics of a service.
    pub async fn characteristics(&self, service: &Service) -> Result<Vec<Characteristic>> {
        let decls = self
            .read_by_type_all(
                service.start,
                service.end,
                Uuid::Uuid16(uuid::CHARACTERISTIC),
            )
            .await?;
        let mut out: Vec<Characteristic> = Vec::new();
        for (h, v) in decls {
            if v.len() != 5 && v.len() != 19 {
                return Err(Error::Protocol("bad characteristic declaration".into()));
            }
            let u = Uuid::from_le_bytes(&v[3..])
                .ok_or_else(|| Error::Protocol("bad characteristic UUID".into()))?;
            if let Some(prev) = out.last_mut() {
                prev.end = h - 1;
            }
            out.push(Characteristic {
                uuid: u,
                name: u.name(),
                declaration: h,
                value_handle: le16(&v, 1)?,
                properties: Properties(v[0]),
                end: service.end,
                descriptors: Vec::new(),
            });
        }
        Ok(out)
    }

    /// The descriptors of a characteristic.
    pub async fn descriptors(&self, c: &Characteristic) -> Result<Vec<Descriptor>> {
        let mut out = Vec::new();
        if c.value_handle >= c.end {
            return Ok(out);
        }
        let mut start = c.value_handle + 1;
        loop {
            let mut pdu = vec![op::FIND_INFO_REQ];
            pdu.extend_from_slice(&start.to_le_bytes());
            pdu.extend_from_slice(&c.end.to_le_bytes());
            let rsp = match self.request(pdu).await {
                Ok(r) => r,
                Err(e) if not_found(&e) => break,
                Err(e) => return Err(e),
            };
            let size = match rsp.get(1) {
                Some(1) => 4,
                Some(2) => 18,
                _ => return Err(Error::Protocol("bad Find Information format".into())),
            };
            let mut last = start;
            for e in rsp[2..].chunks_exact(size) {
                let h = le16(e, 0)?;
                let u = Uuid::from_le_bytes(&e[2..])
                    .ok_or_else(|| Error::Protocol("bad descriptor UUID".into()))?;
                out.push(Descriptor { uuid: u, handle: h });
                last = h;
            }
            if last >= c.end || last < start {
                break;
            }
            start = last + 1;
        }
        Ok(out)
    }

    /// Discovers every primary service with its characteristics and descriptors.
    pub async fn discover(&self) -> Result<Vec<Service>> {
        let mut services = self.services().await?;
        for s in &mut services {
            let mut chars = self.characteristics(s).await?;
            for c in &mut chars {
                c.descriptors = self.descriptors(c).await?;
            }
            s.characteristics = chars;
        }
        Ok(services)
    }

    async fn read_by_type_all(
        &self,
        start: u16,
        end: u16,
        ty: Uuid,
    ) -> Result<Vec<(u16, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut s = start;
        while s <= end {
            let mut pdu = vec![op::READ_BY_TYPE_REQ];
            pdu.extend_from_slice(&s.to_le_bytes());
            pdu.extend_from_slice(&end.to_le_bytes());
            pdu.extend_from_slice(&super::uuid_bytes(&ty));
            let rsp = match self.request(pdu).await {
                Ok(r) => r,
                Err(e) if not_found(&e) => break,
                Err(e) => return Err(e),
            };
            let len = usize::from(
                *rsp.get(1)
                    .ok_or_else(|| Error::Protocol("empty response".into()))?,
            );
            if len < 2 {
                return Err(Error::Protocol("Read By Type entry too short".into()));
            }
            let mut last = s;
            for e in rsp[2..].chunks_exact(len) {
                let h = le16(e, 0)?;
                out.push((h, e[2..].to_vec()));
                last = h;
            }
            if last == 0xffff || last < s {
                break;
            }
            s = last + 1;
        }
        Ok(out)
    }

    /// Reads every attribute of a type in a range: (handle, value).
    pub async fn read_by_type(
        &self,
        start: u16,
        end: u16,
        ty: Uuid,
    ) -> Result<Vec<(u16, Vec<u8>)>> {
        self.read_by_type_all(start, end, ty).await
    }

    /// Reads a value, whole: a value that fills the response is continued
    /// with Read Blob until it ends (a long read).
    pub async fn read(&self, handle: u16) -> Result<Vec<u8>> {
        let mut pdu = vec![op::READ_REQ];
        pdu.extend_from_slice(&handle.to_le_bytes());
        let rsp = self.request(pdu).await?;
        let mut value = rsp[1..].to_vec();
        let full = self.mtu() - 1;
        let mut part = value.len();
        while part == full && value.len() < 512 {
            let mut pdu = vec![op::READ_BLOB_REQ];
            pdu.extend_from_slice(&handle.to_le_bytes());
            pdu.extend_from_slice(&(value.len() as u16).to_le_bytes());
            let rsp = match self.request(pdu).await {
                Ok(r) => r,
                // The value was exactly one PDU long.
                Err(Error::Att { code, .. })
                    if code == ecode::ATTRIBUTE_NOT_LONG || code == ecode::INVALID_OFFSET =>
                {
                    break
                }
                Err(e) => return Err(e),
            };
            part = rsp.len() - 1;
            value.extend_from_slice(&rsp[1..]);
        }
        Ok(value)
    }

    /// Reads a value from an offset (one Read Blob).
    pub async fn read_blob(&self, handle: u16, offset: u16) -> Result<Vec<u8>> {
        let mut pdu = vec![op::READ_BLOB_REQ];
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(&offset.to_le_bytes());
        Ok(self.request(pdu).await?[1..].to_vec())
    }

    /// Reads several values of known lengths in one request; the result is
    /// their concatenation (Read Multiple).
    pub async fn read_multiple(&self, handles: &[u16]) -> Result<Vec<u8>> {
        if handles.len() < 2 {
            return Err(Error::InvalidParameter(
                "Read Multiple needs two or more handles".into(),
            ));
        }
        let mut pdu = vec![op::READ_MULTIPLE_REQ];
        for h in handles {
            pdu.extend_from_slice(&h.to_le_bytes());
        }
        Ok(self.request(pdu).await?[1..].to_vec())
    }

    /// Reads several values in one request, each with its own length (Read
    /// Multiple Variable Length).
    pub async fn read_multiple_variable(&self, handles: &[u16]) -> Result<Vec<Vec<u8>>> {
        let mut pdu = vec![op::READ_MULTIPLE_VAR_REQ];
        for h in handles {
            pdu.extend_from_slice(&h.to_le_bytes());
        }
        let rsp = self.request(pdu).await?;
        let mut out = Vec::new();
        let mut rest = &rsp[1..];
        while rest.len() >= 2 {
            let len = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
            let end = (2 + len).min(rest.len());
            out.push(rest[2..end].to_vec());
            rest = &rest[end..];
        }
        Ok(out)
    }

    /// Writes a value and waits for the response. A value longer than one
    /// PDU is written with Prepare and Execute (a long write).
    pub async fn write(&self, handle: u16, value: &[u8]) -> Result<()> {
        if value.len() <= self.mtu() - 3 {
            let mut pdu = vec![op::WRITE_REQ];
            pdu.extend_from_slice(&handle.to_le_bytes());
            pdu.extend_from_slice(value);
            self.request(pdu).await?;
            return Ok(());
        }
        self.reliable_write(&[(handle, value.to_vec())]).await
    }

    /// Writes without a response.
    pub async fn write_without_response(&self, handle: u16, value: &[u8]) -> Result<()> {
        if value.len() > self.mtu() - 3 {
            return Err(Error::InvalidParameter(format!(
                "{} octets do not fit in one Write Command (MTU {})",
                value.len(),
                self.mtu()
            )));
        }
        let mut pdu = vec![op::WRITE_CMD];
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(value);
        let c = &self.conn;
        c.state.att.command(&c.host, &c.state, &pdu).await
    }

    /// Writes several values atomically with Prepare Write, checking each
    /// echo, then Execute Write; cancels on any mismatch (a reliable write).
    pub async fn reliable_write(&self, writes: &[(u16, Vec<u8>)]) -> Result<()> {
        let chunk = self.mtu() - 5;
        for (handle, value) in writes {
            let mut offset = 0usize;
            loop {
                let part = &value[offset..(offset + chunk).min(value.len())];
                let mut pdu = vec![op::PREPARE_WRITE_REQ];
                pdu.extend_from_slice(&handle.to_le_bytes());
                pdu.extend_from_slice(&(offset as u16).to_le_bytes());
                pdu.extend_from_slice(part);
                let rsp = match self.request(pdu.clone()).await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = self.request(vec![op::EXECUTE_WRITE_REQ, 0x00]).await;
                        return Err(e);
                    }
                };
                if rsp[1..] != pdu[1..] {
                    let _ = self.request(vec![op::EXECUTE_WRITE_REQ, 0x00]).await;
                    return Err(Error::Protocol(
                        "the server echoed a different value; write cancelled".into(),
                    ));
                }
                offset += part.len();
                if offset >= value.len() {
                    break;
                }
            }
        }
        self.request(vec![op::EXECUTE_WRITE_REQ, 0x01]).await?;
        Ok(())
    }

    /// Turns notifications and indications on or off for a characteristic
    /// by writing its Client Characteristic Configuration descriptor (found
    /// by discovery when not yet known). Values arrive as
    /// [`crate::ConnEvent::Notification`].
    pub async fn subscribe(&self, c: &Characteristic, notify: bool, indicate: bool) -> Result<()> {
        if notify && !c.properties.has(Properties::NOTIFY)
            || indicate && !c.properties.has(Properties::INDICATE)
        {
            return Err(Error::InvalidParameter(format!(
                "characteristic {} cannot {}",
                c.uuid,
                if notify { "notify" } else { "indicate" }
            )));
        }
        let cccd = match c.cccd() {
            Some(h) => h,
            None => self
                .descriptors(c)
                .await?
                .iter()
                .find(|d| d.uuid == Uuid::Uuid16(uuid::CCCD))
                .map(|d| d.handle)
                .ok_or_else(|| Error::Protocol("the characteristic has no CCCD".into()))?,
        };
        let v = u16::from(notify) | (u16::from(indicate) << 1);
        self.write(cccd, &v.to_le_bytes()).await
    }

    /// Finds a characteristic by value handle, discovering as needed.
    pub async fn characteristic_at(&self, value_handle: u16) -> Result<Characteristic> {
        for s in self.services().await? {
            if s.start <= value_handle && value_handle <= s.end {
                for mut c in self.characteristics(&s).await? {
                    if c.value_handle == value_handle {
                        c.descriptors = self.descriptors(&c).await?;
                        return Ok(c);
                    }
                }
            }
        }
        Err(Error::InvalidParameter(format!(
            "no characteristic with value handle {value_handle:#06x}"
        )))
    }

    /// Finds a characteristic by UUID (the first one), discovering as needed.
    pub async fn characteristic(&self, u: Uuid) -> Result<Characteristic> {
        for s in self.services().await? {
            for mut c in self.characteristics(&s).await? {
                if c.uuid == u {
                    c.descriptors = self.descriptors(&c).await?;
                    return Ok(c);
                }
            }
        }
        Err(Error::InvalidParameter(format!("no characteristic {u}")))
    }
}
