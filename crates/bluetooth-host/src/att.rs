//! The Attribute Protocol bearer (Core Vol 3, Part F).
//!
//! One task per connection reads ATT PDUs: responses go to the client
//! request waiting for them, requests and commands to our GATT server,
//! notifications and indications to the application (indications are
//! confirmed at once).

use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::connection::{ConnEvent, ConnState};
use crate::error::{Error, Result};
use crate::host::Host;
use crate::l2cap::cid;

/// ATT opcodes.
pub mod op {
    /// Error Response.
    pub const ERROR_RSP: u8 = 0x01;
    /// Exchange MTU Request.
    pub const MTU_REQ: u8 = 0x02;
    /// Exchange MTU Response.
    pub const MTU_RSP: u8 = 0x03;
    /// Find Information Request.
    pub const FIND_INFO_REQ: u8 = 0x04;
    /// Find Information Response.
    pub const FIND_INFO_RSP: u8 = 0x05;
    /// Find By Type Value Request.
    pub const FIND_BY_TYPE_REQ: u8 = 0x06;
    /// Find By Type Value Response.
    pub const FIND_BY_TYPE_RSP: u8 = 0x07;
    /// Read By Type Request.
    pub const READ_BY_TYPE_REQ: u8 = 0x08;
    /// Read By Type Response.
    pub const READ_BY_TYPE_RSP: u8 = 0x09;
    /// Read Request.
    pub const READ_REQ: u8 = 0x0a;
    /// Read Response.
    pub const READ_RSP: u8 = 0x0b;
    /// Read Blob Request.
    pub const READ_BLOB_REQ: u8 = 0x0c;
    /// Read Blob Response.
    pub const READ_BLOB_RSP: u8 = 0x0d;
    /// Read Multiple Request.
    pub const READ_MULTIPLE_REQ: u8 = 0x0e;
    /// Read Multiple Response.
    pub const READ_MULTIPLE_RSP: u8 = 0x0f;
    /// Read By Group Type Request.
    pub const READ_BY_GROUP_REQ: u8 = 0x10;
    /// Read By Group Type Response.
    pub const READ_BY_GROUP_RSP: u8 = 0x11;
    /// Write Request.
    pub const WRITE_REQ: u8 = 0x12;
    /// Write Response.
    pub const WRITE_RSP: u8 = 0x13;
    /// Write Command.
    pub const WRITE_CMD: u8 = 0x52;
    /// Signed Write Command.
    pub const SIGNED_WRITE_CMD: u8 = 0xd2;
    /// Prepare Write Request.
    pub const PREPARE_WRITE_REQ: u8 = 0x16;
    /// Prepare Write Response.
    pub const PREPARE_WRITE_RSP: u8 = 0x17;
    /// Execute Write Request.
    pub const EXECUTE_WRITE_REQ: u8 = 0x18;
    /// Execute Write Response.
    pub const EXECUTE_WRITE_RSP: u8 = 0x19;
    /// Handle Value Notification.
    pub const NOTIFY: u8 = 0x1b;
    /// Handle Value Indication.
    pub const INDICATE: u8 = 0x1d;
    /// Handle Value Confirmation.
    pub const CONFIRM: u8 = 0x1e;
    /// Read Multiple Variable Length Request.
    pub const READ_MULTIPLE_VAR_REQ: u8 = 0x20;
    /// Read Multiple Variable Length Response.
    pub const READ_MULTIPLE_VAR_RSP: u8 = 0x21;
    /// Multiple Handle Value Notification.
    pub const MULTIPLE_NOTIFY: u8 = 0x23;
}

/// ATT error codes.
pub mod ecode {
    /// Invalid Handle.
    pub const INVALID_HANDLE: u8 = 0x01;
    /// Read Not Permitted.
    pub const READ_NOT_PERMITTED: u8 = 0x02;
    /// Write Not Permitted.
    pub const WRITE_NOT_PERMITTED: u8 = 0x03;
    /// Invalid PDU.
    pub const INVALID_PDU: u8 = 0x04;
    /// Insufficient Authentication.
    pub const INSUFFICIENT_AUTHENTICATION: u8 = 0x05;
    /// Request Not Supported.
    pub const REQUEST_NOT_SUPPORTED: u8 = 0x06;
    /// Invalid Offset.
    pub const INVALID_OFFSET: u8 = 0x07;
    /// Insufficient Authorization.
    pub const INSUFFICIENT_AUTHORIZATION: u8 = 0x08;
    /// Prepare Queue Full.
    pub const PREPARE_QUEUE_FULL: u8 = 0x09;
    /// Attribute Not Found.
    pub const ATTRIBUTE_NOT_FOUND: u8 = 0x0a;
    /// Attribute Not Long.
    pub const ATTRIBUTE_NOT_LONG: u8 = 0x0b;
    /// Encryption Key Size Too Short.
    pub const KEY_SIZE_TOO_SHORT: u8 = 0x0c;
    /// Invalid Attribute Value Length.
    pub const INVALID_LENGTH: u8 = 0x0d;
    /// Unlikely Error.
    pub const UNLIKELY: u8 = 0x0e;
    /// Insufficient Encryption.
    pub const INSUFFICIENT_ENCRYPTION: u8 = 0x0f;
    /// Unsupported Group Type.
    pub const UNSUPPORTED_GROUP_TYPE: u8 = 0x10;
    /// Insufficient Resources.
    pub const INSUFFICIENT_RESOURCES: u8 = 0x11;
    /// Value Not Allowed.
    pub const VALUE_NOT_ALLOWED: u8 = 0x13;
    /// CCCD improperly configured.
    pub const CCCD_IMPROPER: u8 = 0xfd;
}

/// The name of an ATT error code.
pub fn error_name(code: u8) -> &'static str {
    match code {
        0x01 => "Invalid Handle",
        0x02 => "Read Not Permitted",
        0x03 => "Write Not Permitted",
        0x04 => "Invalid PDU",
        0x05 => "Insufficient Authentication",
        0x06 => "Request Not Supported",
        0x07 => "Invalid Offset",
        0x08 => "Insufficient Authorization",
        0x09 => "Prepare Queue Full",
        0x0a => "Attribute Not Found",
        0x0b => "Attribute Not Long",
        0x0c => "Encryption Key Size Too Short",
        0x0d => "Invalid Attribute Value Length",
        0x0e => "Unlikely Error",
        0x0f => "Insufficient Encryption",
        0x10 => "Unsupported Group Type",
        0x11 => "Insufficient Resources",
        0x12 => "Database Out Of Sync",
        0x13 => "Value Not Allowed",
        0x80..=0x9f => "Application Error",
        0xfc => "Write Request Rejected",
        0xfd => "Client Characteristic Configuration Descriptor Improperly Configured",
        0xfe => "Procedure Already in Progress",
        0xff => "Out of Range",
        _ => "Reserved",
    }
}

/// The default (and minimum) ATT MTU on LE.
pub const DEFAULT_MTU: u16 = 23;
/// The MTU we offer: room for a 512-octet attribute value in one PDU.
pub const MAX_MTU: u16 = 517;

/// A transaction must complete within 30 s (Core Vol 3, Part F, 3.3.3).
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(30);

struct Pending {
    request: u8,
    tx: oneshot::Sender<Result<Vec<u8>>>,
}

/// One connection's ATT state.
pub(crate) struct Bearer {
    mtu: AtomicU16,
    mtu_exchanged: AtomicBool,
    client: tokio::sync::Mutex<()>,
    pending: Mutex<Option<Pending>>,
    indications: tokio::sync::Mutex<()>,
    confirm: Mutex<Option<oneshot::Sender<()>>>,
}

impl Default for Bearer {
    fn default() -> Self {
        Bearer {
            mtu: AtomicU16::new(DEFAULT_MTU),
            mtu_exchanged: AtomicBool::new(false),
            client: tokio::sync::Mutex::new(()),
            pending: Mutex::new(None),
            indications: tokio::sync::Mutex::new(()),
            confirm: Mutex::new(None),
        }
    }
}

impl Bearer {
    /// The MTU in use.
    pub(crate) fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }

    fn set_mtu(&self, m: u16) {
        self.mtu
            .store(m.clamp(DEFAULT_MTU, MAX_MTU), Ordering::Relaxed);
    }

    pub(crate) fn close(&self) {
        if let Some(p) = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = p.tx.send(Err(Error::Disconnected));
        }
        self.confirm
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }

    /// Sends a request and waits for its response (or Error Response).
    pub(crate) async fn request(
        &self,
        host: &Host,
        conn: &ConnState,
        pdu: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let _one = self.client.lock().await;
        let (tx, rx) = oneshot::channel();
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(Pending {
            request: pdu[0],
            tx,
        });
        conn.send(host, cid::ATT, &pdu).await?;
        match tokio::time::timeout(TRANSACTION_TIMEOUT, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(Error::Disconnected),
            Err(_) => {
                // No further ATT traffic is allowed on this bearer.
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                Err(Error::Timeout("an ATT response"))
            }
        }
    }

    /// Sends a command (no response).
    pub(crate) async fn command(&self, host: &Host, conn: &ConnState, pdu: &[u8]) -> Result<()> {
        conn.send(host, cid::ATT, pdu).await
    }

    /// Sends an indication and waits for the confirmation.
    pub(crate) async fn indicate(
        &self,
        host: &Host,
        conn: &ConnState,
        handle: u16,
        value: &[u8],
    ) -> Result<()> {
        let _one = self.indications.lock().await;
        let (tx, rx) = oneshot::channel();
        *self.confirm.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let mut pdu = vec![op::INDICATE];
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(&value[..value.len().min(usize::from(self.mtu()) - 3)]);
        conn.send(host, cid::ATT, &pdu).await?;
        match tokio::time::timeout(TRANSACTION_TIMEOUT, rx).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Error::Disconnected),
            Err(_) => Err(Error::Timeout("an indication's confirmation")),
        }
    }

    /// Sends a notification, truncated to the MTU as the specification says.
    pub(crate) async fn notify(
        &self,
        host: &Host,
        conn: &ConnState,
        handle: u16,
        value: &[u8],
    ) -> Result<()> {
        let mut pdu = vec![op::NOTIFY];
        pdu.extend_from_slice(&handle.to_le_bytes());
        pdu.extend_from_slice(&value[..value.len().min(usize::from(self.mtu()) - 3)]);
        conn.send(host, cid::ATT, &pdu).await
    }

    /// Exchanges the MTU (client side); returns the MTU in use.
    pub(crate) async fn exchange_mtu(
        &self,
        host: &Host,
        conn: &ConnState,
        ours: u16,
    ) -> Result<u16> {
        let ours = ours.clamp(DEFAULT_MTU, MAX_MTU);
        let mut pdu = vec![op::MTU_REQ];
        pdu.extend_from_slice(&ours.to_le_bytes());
        let rsp = self.request(host, conn, pdu).await?;
        let theirs = match rsp.as_slice() {
            [op::MTU_RSP, a, b] => u16::from_le_bytes([*a, *b]),
            _ => return Err(Error::Protocol("malformed Exchange MTU Response".into())),
        };
        let m = ours.min(theirs).max(DEFAULT_MTU);
        self.set_mtu(m);
        self.mtu_exchanged.store(true, Ordering::Relaxed);
        let _ = conn.events.send(ConnEvent::MtuExchanged(m));
        Ok(m)
    }
}

/// Whether an opcode is a response, and to which request.
fn response_to(opcode: u8) -> Option<u8> {
    match opcode {
        op::MTU_RSP
        | op::FIND_INFO_RSP
        | op::FIND_BY_TYPE_RSP
        | op::READ_BY_TYPE_RSP
        | op::READ_RSP
        | op::READ_BLOB_RSP
        | op::READ_MULTIPLE_RSP
        | op::READ_BY_GROUP_RSP
        | op::WRITE_RSP
        | op::PREPARE_WRITE_RSP
        | op::EXECUTE_WRITE_RSP
        | op::READ_MULTIPLE_VAR_RSP => Some(opcode - 1),
        _ => None,
    }
}

/// Reads one connection's ATT PDUs until it closes.
pub(crate) async fn run(host: Host, conn: Arc<ConnState>, mut rx: mpsc::Receiver<Vec<u8>>) {
    loop {
        let pdu = tokio::select! {
            p = rx.recv() => match p { Some(p) => p, None => return },
            _ = conn.wait_closed() => return,
        };
        if let Err(e) = on_pdu(&host, &conn, pdu).await {
            tracing::debug!("ATT on {:#05x}: {e}", conn.handle);
        }
    }
}

async fn on_pdu(host: &Host, conn: &Arc<ConnState>, pdu: Vec<u8>) -> Result<()> {
    let Some(&opcode) = pdu.first() else {
        return Ok(());
    };
    let bearer = &conn.att;
    if opcode == op::ERROR_RSP {
        if pdu.len() == 5 {
            let (request, handle, code) = (pdu[1], u16::from_le_bytes([pdu[2], pdu[3]]), pdu[4]);
            let mut p = bearer.pending.lock().unwrap_or_else(|e| e.into_inner());
            if p.as_ref().is_some_and(|p| p.request == request) {
                if let Some(p) = p.take() {
                    let _ = p.tx.send(Err(Error::Att {
                        request,
                        handle,
                        code,
                    }));
                }
            }
        }
        return Ok(());
    }
    if let Some(request) = response_to(opcode) {
        let mut p = bearer.pending.lock().unwrap_or_else(|e| e.into_inner());
        if p.as_ref().is_some_and(|p| p.request == request) {
            if let Some(p) = p.take() {
                let _ = p.tx.send(Ok(pdu));
            }
        } else {
            tracing::debug!("unexpected ATT response {opcode:#04x}");
        }
        return Ok(());
    }
    match opcode {
        op::NOTIFY | op::INDICATE if pdu.len() >= 3 => {
            let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
            let indication = opcode == op::INDICATE;
            let _ = conn.events.send(ConnEvent::Notification {
                handle,
                value: pdu[3..].to_vec(),
                indication,
            });
            if indication {
                bearer.command(host, conn, &[op::CONFIRM]).await?;
            }
        }
        op::MULTIPLE_NOTIFY => {
            let mut rest = &pdu[1..];
            while rest.len() >= 4 {
                let handle = u16::from_le_bytes([rest[0], rest[1]]);
                let len = usize::from(u16::from_le_bytes([rest[2], rest[3]]));
                let Some(value) = rest.get(4..4 + len) else {
                    break;
                };
                let _ = conn.events.send(ConnEvent::Notification {
                    handle,
                    value: value.to_vec(),
                    indication: false,
                });
                rest = &rest[4 + len..];
            }
        }
        op::CONFIRM => {
            if let Some(tx) = bearer
                .confirm
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                let _ = tx.send(());
            }
        }
        op::MTU_REQ => {
            let theirs = match pdu.as_slice() {
                [_, a, b] => u16::from_le_bytes([*a, *b]),
                _ => return send_error(host, conn, opcode, 0, ecode::INVALID_PDU).await,
            };
            let mut rsp = vec![op::MTU_RSP];
            rsp.extend_from_slice(&MAX_MTU.to_le_bytes());
            bearer.command(host, conn, &rsp).await?;
            // The new MTU applies after the response is sent.
            bearer.set_mtu(theirs.min(MAX_MTU));
            bearer.mtu_exchanged.store(true, Ordering::Relaxed);
            let _ = conn.events.send(ConnEvent::MtuExchanged(bearer.mtu()));
        }
        _ => {
            let rsp = host.inner.gatt.handle(host, conn, &pdu).await;
            if let Some(rsp) = rsp {
                bearer.command(host, conn, &rsp).await?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn send_error(
    host: &Host,
    conn: &ConnState,
    request: u8,
    handle: u16,
    code: u8,
) -> Result<()> {
    conn.att
        .command(host, conn, &error_pdu(request, handle, code))
        .await
}

/// An Error Response PDU.
pub(crate) fn error_pdu(request: u8, handle: u16, code: u8) -> Vec<u8> {
    let h = handle.to_le_bytes();
    vec![op::ERROR_RSP, request, h[0], h[1], code]
}
