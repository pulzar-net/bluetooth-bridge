//! Commands and ACL data, host to controller.
//!
//! Commands go one at a time: the next is sent once the controller has
//! answered the last with Command Complete or Command Status. Every
//! controller allows that, and it keeps answers unambiguous.
//!
//! ACL data is metered by the controller's buffer count: a packet is sent
//! only when the controller has a free buffer, and Number Of Completed
//! Packets gives buffers back (Core Vol 4, Part E, 4.1).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bt_hci::cmd::{AsyncCmd, Cmd, SyncCmd};
use bt_hci::{FromHciBytes, WriteHci};
use tokio::sync::{oneshot, Semaphore};

use crate::error::{Error, Result};
use crate::transport::{indicator, PacketWriter};

/// How long a command may take before the controller is considered stuck.
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// The controller's answer to a command.
#[derive(Debug)]
pub(crate) enum Reply {
    /// Command Complete: the status and the return parameters after it.
    Complete { status: u8, params: Vec<u8> },
    /// Command Status.
    Status(u8),
}

struct Pending {
    opcode: u16,
    tx: oneshot::Sender<Reply>,
}

/// The host side of the HCI link.
pub(crate) struct Hci {
    writer: tokio::sync::Mutex<PacketWriter>,
    cmd_lock: tokio::sync::Mutex<()>,
    pending: Mutex<Option<Pending>>,
    acl_credits: Semaphore,
    acl_mtu: AtomicUsize,
    in_flight: Mutex<HashMap<u16, Arc<AtomicU16>>>,
}

impl Hci {
    pub(crate) fn new(writer: PacketWriter) -> Self {
        Hci {
            writer: tokio::sync::Mutex::new(writer),
            cmd_lock: tokio::sync::Mutex::new(()),
            pending: Mutex::new(None),
            acl_credits: Semaphore::new(0),
            acl_mtu: AtomicUsize::new(27),
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    /// Sends a command and waits for its answer.
    pub(crate) async fn command(
        &self,
        opcode: u16,
        packet: &[u8],
        timeout: Duration,
    ) -> Result<Reply> {
        let _one_at_a_time = self.cmd_lock.lock().await;
        let (tx, rx) = oneshot::channel();
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(Pending { opcode, tx });
        self.writer
            .lock()
            .await
            .write(indicator::COMMAND, packet)
            .await?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(_)) => Err(Error::Stopped),
            Err(_) => {
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                tracing::error!("controller did not answer command {opcode:#06x}");
                Err(Error::Timeout("the controller to answer a command"))
            }
        }
    }

    /// Runs a command that completes with Command Complete, and parses its
    /// return parameters.
    pub(crate) async fn exec<C: SyncCmd>(&self, cmd: &C) -> Result<C::Return> {
        let opcode = C::OPCODE.to_raw();
        match self.command(opcode, &encode(cmd), COMMAND_TIMEOUT).await? {
            Reply::Complete { status: 0, params } => C::Return::from_hci_bytes(&params)
                .map(|(r, _)| r)
                .map_err(|e| {
                    Error::Protocol(format!("return parameters of command {opcode:#06x}: {e:?}"))
                }),
            Reply::Complete { status, .. } | Reply::Status(status) => {
                Err(Error::hci(opcode, status))
            }
        }
    }

    /// Runs a command that answers with Command Status; the outcome arrives
    /// later as an event.
    pub(crate) async fn exec_async<C: AsyncCmd>(&self, cmd: &C) -> Result<()> {
        let opcode = C::OPCODE.to_raw();
        match self.command(opcode, &encode(cmd), COMMAND_TIMEOUT).await? {
            Reply::Status(0) | Reply::Complete { status: 0, .. } => Ok(()),
            Reply::Status(status) | Reply::Complete { status, .. } => {
                Err(Error::hci(opcode, status))
            }
        }
    }

    /// The reader saw Command Complete.
    pub(crate) fn complete(&self, opcode: u16, ret: &[u8]) {
        if opcode == 0 {
            return; // The controller saying it is ready; nothing waits for it.
        }
        let (status, params) = match ret.split_first() {
            Some((s, p)) => (*s, p.to_vec()),
            None => (0, Vec::new()),
        };
        self.deliver(opcode, Reply::Complete { status, params });
    }

    /// The reader saw Command Status.
    pub(crate) fn status(&self, opcode: u16, status: u8) {
        if opcode != 0 {
            self.deliver(opcode, Reply::Status(status));
        }
    }

    fn deliver(&self, opcode: u16, reply: Reply) {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        match p.take() {
            Some(pending) if pending.opcode == opcode => {
                let _ = pending.tx.send(reply);
            }
            other => {
                tracing::warn!("answer to command {opcode:#06x}, which is not the one waiting");
                *p = other;
            }
        }
    }

    /// Sets the ACL buffer size and count, once, from the controller's answer.
    pub(crate) fn set_acl_buffers(&self, mtu: u16, count: u16) {
        self.acl_mtu
            .store(usize::from(mtu.max(27)), Ordering::Relaxed);
        self.acl_credits.add_permits(usize::from(count.max(1)));
    }

    /// Starts counting a connection's packets.
    pub(crate) fn open_handle(&self, handle: u16) -> Arc<AtomicU16> {
        let c = Arc::new(AtomicU16::new(0));
        self.in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(handle, c.clone());
        c
    }

    /// The controller freed `n` buffers of `handle`.
    pub(crate) fn completed(&self, handle: u16, n: u16) {
        if let Some(c) = self
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&handle)
        {
            let mut cur = c.load(Ordering::Acquire);
            while let Err(now) = c.compare_exchange_weak(
                cur,
                cur.saturating_sub(n),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                cur = now;
            }
        }
        self.acl_credits.add_permits(usize::from(n));
    }

    /// A connection closed: the controller dropped its queued packets, so
    /// their buffers are free again.
    pub(crate) fn close_handle(&self, handle: u16) {
        if let Some(c) = self
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&handle)
        {
            self.acl_credits
                .add_permits(usize::from(c.swap(0, Ordering::AcqRel)));
        }
    }

    /// Sends one L2CAP PDU (basic header included) on a connection, split
    /// into ACL packets the controller can take. The caller holds the
    /// connection's send lock so fragments of two PDUs never interleave.
    pub(crate) async fn send_acl(
        &self,
        handle: u16,
        pdu: &[u8],
        in_flight: &AtomicU16,
    ) -> Result<()> {
        let mtu = self.acl_mtu.load(Ordering::Relaxed);
        for (i, frag) in pdu.chunks(mtu).enumerate() {
            let permit = self
                .acl_credits
                .acquire()
                .await
                .map_err(|_| Error::Stopped)?;
            if !self
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&handle)
            {
                return Err(Error::Disconnected);
            }
            permit.forget();
            in_flight.fetch_add(1, Ordering::AcqRel);
            // Packet boundary: first non-flushable (00), then continuing (01).
            let pb: u16 = if i == 0 { 0b00 } else { 0b01 };
            let mut pkt = Vec::with_capacity(4 + frag.len());
            pkt.extend_from_slice(&(handle | (pb << 12)).to_le_bytes());
            pkt.extend_from_slice(&(frag.len() as u16).to_le_bytes());
            pkt.extend_from_slice(frag);
            self.writer.lock().await.write(indicator::ACL, &pkt).await?;
        }
        Ok(())
    }

    /// Wakes everything waiting on the controller: the host is stopping.
    pub(crate) fn shutdown(&self) {
        self.acl_credits.close();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
}

/// A command's packet: header and parameters.
pub(crate) fn encode<C: Cmd>(cmd: &C) -> Vec<u8> {
    let mut v = Vec::with_capacity(WriteHci::size(cmd));
    // Writing into a Vec cannot fail.
    let _ = WriteHci::write_hci(cmd, &mut v);
    v
}

/// Reassembles ACL packets into L2CAP PDUs, per connection.
#[derive(Default)]
pub(crate) struct Reassembly {
    partial: HashMap<u16, Vec<u8>>,
}

/// The largest L2CAP PDU accepted (basic header plus 65535 octets).
const MAX_PDU: usize = 4 + 65_535;

impl Reassembly {
    /// Adds an ACL packet (header included); returns the connection handle
    /// and a whole L2CAP PDU when one is complete.
    pub(crate) fn push(&mut self, acl: &[u8]) -> Option<(u16, Vec<u8>)> {
        if acl.len() < 4 {
            return None;
        }
        let hdr = u16::from_le_bytes([acl[0], acl[1]]);
        let handle = hdr & 0x0fff;
        let pb = (hdr >> 12) & 0b11;
        let len = usize::from(u16::from_le_bytes([acl[2], acl[3]]));
        let data = acl.get(4..4 + len)?;
        let buf = match pb {
            // First packet (flushable or not): a new PDU.
            0b10 | 0b00 => {
                if self.partial.contains_key(&handle) {
                    tracing::debug!("handle {handle:#05x}: new PDU before the last was complete; dropping the last");
                }
                self.partial.insert(handle, data.to_vec());
                self.partial.get_mut(&handle)?
            }
            0b01 => {
                let b = self.partial.get_mut(&handle)?;
                b.extend_from_slice(data);
                b
            }
            _ => return None,
        };
        if buf.len() >= 4 {
            let want = 4 + usize::from(u16::from_le_bytes([buf[0], buf[1]]));
            if buf.len() >= want {
                let mut pdu = self.partial.remove(&handle)?;
                if pdu.len() > want {
                    tracing::debug!(
                        "handle {handle:#05x}: {} bytes past the end of a PDU",
                        pdu.len() - want
                    );
                    pdu.truncate(want);
                }
                return Some((handle, pdu));
            }
        }
        if buf.len() > MAX_PDU {
            self.partial.remove(&handle);
        }
        None
    }

    /// Forgets a closed connection's partial PDU.
    pub(crate) fn close(&mut self, handle: u16) {
        self.partial.remove(&handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_fragments() {
        let mut r = Reassembly::default();
        // L2CAP: length 5, CID 4, payload 01 02 03 04 05, split over three ACL packets.
        assert!(r
            .push(&[0x40, 0x20, 0x03, 0x00, 0x05, 0x00, 0x04])
            .is_none());
        assert!(r
            .push(&[0x40, 0x10, 0x03, 0x00, 0x00, 0x01, 0x02])
            .is_none());
        let (h, pdu) = r.push(&[0x40, 0x10, 0x03, 0x00, 0x03, 0x04, 0x05]).unwrap();
        assert_eq!(h, 0x040);
        assert_eq!(pdu, vec![0x05, 0x00, 0x04, 0x00, 1, 2, 3, 4, 5]);
        // A continuation with nothing started is dropped.
        assert!(r.push(&[0x41, 0x10, 0x01, 0x00, 0x00]).is_none());
        // A packet shorter than its header says is dropped.
        assert!(r.push(&[0x40, 0x20, 0x09, 0x00, 0x00]).is_none());
    }
}
