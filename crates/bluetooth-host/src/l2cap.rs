//! L2CAP on LE (Core Vol 3, Part A): the fixed channels (ATT, signaling,
//! SMP), the LE signaling channel, and credit-based connection-oriented
//! channels, both the LE Credit Based (0x14) and the enhanced Credit Based
//! (0x17) forms.
//!
//! Inbound flow control is real: we grant a credit back only when the
//! application has taken the SDU that used it, so a fast peer and a slow
//! reader cannot grow our memory.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::connection::{ConnState, Connection, ParamsRequest, Role};
use crate::error::{Error, Result};
use crate::host::Host;

/// The fixed channel identifiers on LE.
pub mod cid {
    /// Attribute protocol.
    pub const ATT: u16 = 0x0004;
    /// LE signaling.
    pub const SIGNALING: u16 = 0x0005;
    /// Security Manager.
    pub const SMP: u16 = 0x0006;
    /// First dynamically allocated channel.
    pub const DYNAMIC_FIRST: u16 = 0x0040;
    /// Last dynamically allocated channel on LE.
    pub const DYNAMIC_LAST: u16 = 0x007f;
}

mod code {
    pub const COMMAND_REJECT: u8 = 0x01;
    pub const DISCONNECTION_REQ: u8 = 0x06;
    pub const DISCONNECTION_RSP: u8 = 0x07;
    pub const CONN_PARAM_UPDATE_REQ: u8 = 0x12;
    pub const CONN_PARAM_UPDATE_RSP: u8 = 0x13;
    pub const LE_CREDIT_CONN_REQ: u8 = 0x14;
    pub const LE_CREDIT_CONN_RSP: u8 = 0x15;
    pub const FLOW_CONTROL_CREDIT: u8 = 0x16;
    pub const CREDIT_CONN_REQ: u8 = 0x17;
    pub const CREDIT_CONN_RSP: u8 = 0x18;
}

/// Routes a whole L2CAP PDU (basic header included) to its channel.
pub(crate) fn dispatch(host: &Host, handle: u16, pdu: Vec<u8>) {
    let Some(conn) = host.state(handle) else {
        return;
    };
    if pdu.len() < 4 {
        return;
    }
    let channel = u16::from_le_bytes([pdu[2], pdu[3]]);
    let payload = pdu[4..].to_vec();
    let sent = match channel {
        cid::ATT => conn.att_tx.try_send(payload).is_ok(),
        cid::SIGNALING => conn.sig_tx.try_send(payload).is_ok(),
        cid::SMP => conn.smp_tx.try_send(payload).is_ok(),
        c => {
            on_k_frame(host, &conn, c, payload);
            true
        }
    };
    if !sent {
        tracing::warn!(
            "connection {handle:#05x}: channel {channel:#06x} is backed up; dropping a PDU"
        );
    }
}

/// A signaling response: its code and data.
type Response = (u8, Vec<u8>);

/// Outstanding signaling requests, by identifier.
#[derive(Default)]
pub(crate) struct Signaling {
    next_id: AtomicU8,
    pending: Mutex<HashMap<u8, oneshot::Sender<Response>>>,
}

impl Signaling {
    fn id(&self) -> u8 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}

const RTX: Duration = Duration::from_secs(30);

/// Sends a signaling request and waits for its response (code, data).
async fn request(host: &Host, conn: &ConnState, code: u8, data: &[u8]) -> Result<(u8, Vec<u8>)> {
    let id = conn.sig.id();
    let (tx, rx) = oneshot::channel();
    conn.sig
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, tx);
    send_signal(host, conn, code, id, data).await?;
    match tokio::time::timeout(RTX, rx).await {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(_)) => Err(Error::Disconnected),
        Err(_) => {
            conn.sig
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            Err(Error::Timeout("an L2CAP signaling response"))
        }
    }
}

async fn send_signal(host: &Host, conn: &ConnState, code: u8, id: u8, data: &[u8]) -> Result<()> {
    let mut v = Vec::with_capacity(4 + data.len());
    v.push(code);
    v.push(id);
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    conn.send(host, cid::SIGNALING, &v).await
}

/// Handles the LE signaling channel for one connection.
pub(crate) async fn run_signaling(
    host: Host,
    conn: Arc<ConnState>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    loop {
        let pdu = tokio::select! {
            p = rx.recv() => match p { Some(p) => p, None => return },
            _ = conn.wait_closed() => return,
        };
        // One C-frame may hold one command on LE.
        if pdu.len() < 4 {
            continue;
        }
        let (code, id) = (pdu[0], pdu[1]);
        let len = usize::from(u16::from_le_bytes([pdu[2], pdu[3]]));
        let Some(data) = pdu.get(4..4 + len) else {
            let _ = send_signal(&host, &conn, code::COMMAND_REJECT, id, &[0x00, 0x00]).await;
            continue;
        };
        if let Err(e) = on_signal(&host, &conn, code, id, data).await {
            tracing::debug!("signaling on {:#05x}: {e}", conn.handle);
        }
    }
}

fn u16_at(d: &[u8], i: usize) -> u16 {
    match d.get(i..i + 2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

async fn on_signal(
    host: &Host,
    conn: &Arc<ConnState>,
    code: u8,
    id: u8,
    data: &[u8],
) -> Result<()> {
    match code {
        // Responses: hand to whoever asked.
        code::COMMAND_REJECT
        | code::DISCONNECTION_RSP
        | code::CONN_PARAM_UPDATE_RSP
        | code::LE_CREDIT_CONN_RSP
        | code::CREDIT_CONN_RSP => {
            if let Some(tx) = conn
                .sig
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id)
            {
                let _ = tx.send((code, data.to_vec()));
            }
            Ok(())
        }
        code::CONN_PARAM_UPDATE_REQ if data.len() == 8 => {
            let p = ParamsRequest {
                interval_min: u16_at(data, 0),
                interval_max: u16_at(data, 2),
                latency: u16_at(data, 4),
                timeout: u16_at(data, 6),
            };
            if conn.role != Role::Central {
                // Only a central may be asked.
                return send_signal(host, conn, code::COMMAND_REJECT, id, &[0x00, 0x00]).await;
            }
            let ok = p.check().is_ok();
            send_signal(
                host,
                conn,
                code::CONN_PARAM_UPDATE_RSP,
                id,
                &u16::from(!ok).to_le_bytes(),
            )
            .await?;
            if ok {
                let c = Connection::new(host.clone(), conn.clone());
                tokio::spawn(async move {
                    if let Err(e) = c.update_params(p).await {
                        tracing::info!(
                            "peripheral's parameter request on {:#05x} failed: {e}",
                            c.handle()
                        );
                    }
                });
            }
            Ok(())
        }
        code::LE_CREDIT_CONN_REQ if data.len() == 10 => {
            let (spsm, scid, mtu, mps, credits) = (
                u16_at(data, 0),
                u16_at(data, 2),
                u16_at(data, 4),
                u16_at(data, 6),
                u16_at(data, 8),
            );
            let (result, dcid, our_mtu) = accept(host, conn, spsm, &[scid], mtu, mps, credits);
            let mut r = Vec::with_capacity(10);
            r.extend_from_slice(&dcid.first().copied().unwrap_or(0).to_le_bytes());
            r.extend_from_slice(&our_mtu.to_le_bytes());
            r.extend_from_slice(&LOCAL_MPS.to_le_bytes());
            r.extend_from_slice(&LOCAL_CREDITS.to_le_bytes());
            r.extend_from_slice(&result.to_le_bytes());
            send_signal(host, conn, code::LE_CREDIT_CONN_RSP, id, &r).await
        }
        code::CREDIT_CONN_REQ
            if data.len() >= 10 && data.len() <= 18 && data.len().is_multiple_of(2) =>
        {
            let (spsm, mtu, mps, credits) = (
                u16_at(data, 0),
                u16_at(data, 2),
                u16_at(data, 4),
                u16_at(data, 6),
            );
            let scids: Vec<u16> = data[8..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            let (result, dcids, our_mtu) = accept(host, conn, spsm, &scids, mtu, mps, credits);
            let mut r = Vec::new();
            r.extend_from_slice(&our_mtu.to_le_bytes());
            r.extend_from_slice(&LOCAL_MPS.to_le_bytes());
            r.extend_from_slice(&LOCAL_CREDITS.to_le_bytes());
            r.extend_from_slice(&result.to_le_bytes());
            for i in 0..scids.len() {
                r.extend_from_slice(&dcids.get(i).copied().unwrap_or(0).to_le_bytes());
            }
            send_signal(host, conn, code::CREDIT_CONN_RSP, id, &r).await
        }
        code::FLOW_CONTROL_CREDIT if data.len() == 4 => {
            let (c, n) = (u16_at(data, 0), u16_at(data, 2));
            let coc = conn.coc.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(end) = coc.values().find(|e| e.remote_cid == c) {
                // The total may not exceed 65535; a peer that overflows it is broken.
                if end.tx_credits.available_permits() + usize::from(n) <= 65_535 {
                    end.tx_credits.add_permits(usize::from(n));
                }
            }
            Ok(())
        }
        code::DISCONNECTION_REQ if data.len() == 4 => {
            let (dcid, scid) = (u16_at(data, 0), u16_at(data, 2));
            conn.coc
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&dcid);
            send_signal(host, conn, code::DISCONNECTION_RSP, id, data).await?;
            tracing::debug!("peer closed channel {dcid:#06x}/{scid:#06x}");
            Ok(())
        }
        _ => send_signal(host, conn, code::COMMAND_REJECT, id, &[0x00, 0x00]).await,
    }
}

/// Our MPS: the largest K-frame payload we take (fits one 251-octet LL PDU
/// with the L2CAP header).
const LOCAL_MPS: u16 = 247;
/// Credits we grant up front, and keep topped up as SDUs are taken.
const LOCAL_CREDITS: u16 = 16;

/// Decides an incoming channel request: (result, our CIDs, our MTU).
#[allow(clippy::too_many_arguments)]
fn accept(
    host: &Host,
    conn: &Arc<ConnState>,
    spsm: u16,
    scids: &[u16],
    mtu: u16,
    mps: u16,
    credits: u16,
) -> (u16, Vec<u16>, u16) {
    let server = host
        .inner
        .l2cap_servers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&spsm)
        .cloned();
    let Some((local_mtu, listener)) = server else {
        return (0x0002, vec![], 0); // SPSM not supported
    };
    if mtu < 23 || mps < 23 {
        return (0x000c, vec![], 0); // unacceptable parameters
    }
    let mut dcids = Vec::new();
    for &scid in scids {
        if !(cid::DYNAMIC_FIRST..=cid::DYNAMIC_LAST).contains(&scid) {
            return (0x0009, vec![], 0); // invalid source CID
        }
        match open_end(conn, scid, mtu, mps, credits, local_mtu) {
            Some((local, ch)) => {
                dcids.push(local);
                let channel = Channel::new(Connection::new(host.clone(), conn.clone()), ch);
                if listener.try_send(channel).is_err() {
                    return (0x0004, vec![], 0); // no resources
                }
            }
            None => return (0x0004, vec![], 0),
        }
    }
    (0, dcids, local_mtu)
}

/// The receiving side's state of one channel, kept in the connection.
pub(crate) struct ChannelEnd {
    remote_cid: u16,
    tx_credits: Arc<Semaphore>,
    sdus: mpsc::Sender<(Vec<u8>, u16)>,
    partial: Option<(usize, Vec<u8>)>,
    /// K-frames in the SDU being reassembled.
    frames: u16,
    /// Credits we have granted that the peer has not used yet.
    rx_credits: u16,
    local_mtu: u16,
}

struct NewChannel {
    local_cid: u16,
    remote_cid: u16,
    remote_mtu: u16,
    remote_mps: u16,
    local_mtu: u16,
    tx_credits: Arc<Semaphore>,
    sdus: mpsc::Receiver<(Vec<u8>, u16)>,
}

fn open_end(
    conn: &ConnState,
    remote_cid: u16,
    remote_mtu: u16,
    remote_mps: u16,
    credits: u16,
    local_mtu: u16,
) -> Option<(u16, NewChannel)> {
    let mut coc = conn.coc.lock().unwrap_or_else(|e| e.into_inner());
    let local = (cid::DYNAMIC_FIRST..=cid::DYNAMIC_LAST).find(|c| !coc.contains_key(c))?;
    let tx_credits = Arc::new(Semaphore::new(usize::from(credits)));
    let (tx, rx) = mpsc::channel(usize::from(LOCAL_CREDITS));
    coc.insert(
        local,
        ChannelEnd {
            remote_cid,
            tx_credits: tx_credits.clone(),
            sdus: tx,
            partial: None,
            frames: 0,
            rx_credits: LOCAL_CREDITS,
            local_mtu,
        },
    );
    Some((
        local,
        NewChannel {
            local_cid: local,
            remote_cid,
            remote_mtu,
            remote_mps,
            local_mtu,
            tx_credits,
            sdus: rx,
        },
    ))
}

fn on_k_frame(host: &Host, conn: &Arc<ConnState>, local: u16, frame: Vec<u8>) {
    let mut coc = conn.coc.lock().unwrap_or_else(|e| e.into_inner());
    let Some(end) = coc.get_mut(&local) else {
        tracing::debug!("K-frame for unknown channel {local:#06x}");
        return;
    };
    end.frames = end.frames.saturating_add(1);
    if end.rx_credits == 0 {
        // The peer sent without credits: close the channel (Core Vol 3, Part A, 10.1).
        tracing::warn!("channel {local:#06x}: peer exceeded its credits; closing it");
        let remote = end.remote_cid;
        coc.remove(&local);
        drop(coc);
        let (host, conn) = (host.clone(), conn.clone());
        tokio::spawn(async move {
            let mut d = local.to_le_bytes().to_vec();
            d.extend_from_slice(&remote.to_le_bytes());
            let _ = request(&host, &conn, code::DISCONNECTION_REQ, &d).await;
        });
        return;
    }
    end.rx_credits -= 1;
    let (sdu_len, data) = match end.partial.take() {
        None => {
            if frame.len() < 2 {
                return;
            }
            (
                usize::from(u16::from_le_bytes([frame[0], frame[1]])),
                frame[2..].to_vec(),
            )
        }
        Some((want, mut have)) => {
            have.extend_from_slice(&frame);
            (want, have)
        }
    };
    if sdu_len > usize::from(end.local_mtu) || data.len() > sdu_len {
        // Its frames' credits come back as if it had been read.
        tracing::warn!("channel {local:#06x}: SDU larger than our MTU or its length; dropping it");
        let frames = std::mem::take(&mut end.frames);
        let _ = end.sdus.try_send((Vec::new(), frames));
        return;
    }
    if data.len() == sdu_len {
        let frames = std::mem::take(&mut end.frames);
        if end.sdus.try_send((data, frames)).is_err() {
            tracing::warn!("channel {local:#06x}: application is not reading; dropping an SDU");
        }
    } else {
        end.partial = Some((sdu_len, data));
    }
}

/// Registers a server for `spsm`: incoming channels arrive on the receiver.
pub fn listen(host: &Host, spsm: u16, mtu: u16) -> mpsc::Receiver<Channel> {
    let (tx, rx) = mpsc::channel(8);
    host.inner
        .l2cap_servers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(spsm, (mtu.max(23), tx));
    rx
}

/// Opens an LE credit-based channel.
pub(crate) async fn connect(conn: &Connection, spsm: u16, mtu: u16) -> Result<Channel> {
    let mtu = mtu.max(23);
    let (local, new) = open_end(&conn.state, 0, 0, 0, 0, mtu)
        .ok_or(Error::Protocol("no free channel identifiers".into()))?;
    let mut d = Vec::with_capacity(10);
    d.extend_from_slice(&spsm.to_le_bytes());
    d.extend_from_slice(&local.to_le_bytes());
    d.extend_from_slice(&mtu.to_le_bytes());
    d.extend_from_slice(&LOCAL_MPS.to_le_bytes());
    d.extend_from_slice(&LOCAL_CREDITS.to_le_bytes());
    let r = request(&conn.host, &conn.state, code::LE_CREDIT_CONN_REQ, &d).await;
    let fail = |e| {
        conn.state
            .coc
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&local);
        e
    };
    let (code, rsp) = r.map_err(fail)?;
    if code != code::LE_CREDIT_CONN_RSP || rsp.len() != 10 {
        return Err(fail(Error::Protocol("channel request rejected".into())));
    }
    let (dcid, rmtu, rmps, credits, result) = (
        u16_at(&rsp, 0),
        u16_at(&rsp, 2),
        u16_at(&rsp, 4),
        u16_at(&rsp, 6),
        u16_at(&rsp, 8),
    );
    if result != 0 {
        return Err(fail(Error::Protocol(format!(
            "channel refused, result {result:#06x}"
        ))));
    }
    {
        let mut coc = conn.state.coc.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(end) = coc.get_mut(&local) {
            end.remote_cid = dcid;
            end.tx_credits.add_permits(usize::from(credits));
        }
    }
    Ok(Channel::new(
        conn.clone(),
        NewChannel {
            remote_cid: dcid,
            remote_mtu: rmtu,
            remote_mps: rmps,
            ..new
        },
    ))
}

/// An LE credit-based channel.
pub struct Channel {
    conn: Connection,
    local_cid: u16,
    remote_cid: u16,
    remote_mtu: u16,
    remote_mps: u16,
    local_mtu: u16,
    tx_credits: Arc<Semaphore>,
    sdus: mpsc::Receiver<(Vec<u8>, u16)>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("local_cid", &self.local_cid)
            .field("remote_cid", &self.remote_cid)
            .field("remote_mtu", &self.remote_mtu)
            .finish()
    }
}

impl Channel {
    fn new(conn: Connection, n: NewChannel) -> Self {
        Channel {
            conn,
            local_cid: n.local_cid,
            remote_cid: n.remote_cid,
            remote_mtu: n.remote_mtu,
            remote_mps: n.remote_mps.max(23),
            local_mtu: n.local_mtu,
            tx_credits: n.tx_credits,
            sdus: n.sdus,
        }
    }

    /// The largest SDU the peer accepts.
    pub fn peer_mtu(&self) -> u16 {
        self.remote_mtu
    }

    /// The largest SDU we accept.
    pub fn mtu(&self) -> u16 {
        self.local_mtu
    }

    /// Our channel identifier.
    pub fn cid(&self) -> u16 {
        self.local_cid
    }

    /// Sends one SDU, waiting for credits as needed.
    pub async fn send(&self, sdu: &[u8]) -> Result<()> {
        if sdu.len() > usize::from(self.remote_mtu) {
            return Err(Error::InvalidParameter(format!(
                "SDU of {} octets over the peer's MTU {}",
                sdu.len(),
                self.remote_mtu
            )));
        }
        let mps = usize::from(self.remote_mps);
        let mut first = Vec::with_capacity(mps.min(sdu.len() + 2));
        first.extend_from_slice(&(sdu.len() as u16).to_le_bytes());
        let n = sdu.len().min(mps - 2);
        first.extend_from_slice(&sdu[..n]);
        let mut frames = vec![first];
        frames.extend(sdu[n..].chunks(mps).map(|c| c.to_vec()));
        for f in frames {
            let permit = tokio::select! {
                p = self.tx_credits.acquire() => p.map_err(|_| Error::Disconnected)?,
                _ = self.conn.state.wait_closed() => return Err(Error::Disconnected),
            };
            permit.forget();
            self.conn
                .state
                .send(&self.conn.host, self.remote_cid, &f)
                .await?;
        }
        Ok(())
    }

    /// The next SDU; `None` once the channel or connection closes.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let (sdu, frames) = loop {
            let (sdu, frames) = tokio::select! {
                s = self.sdus.recv() => s?,
                _ = self.conn.state.wait_closed() => return None,
            };
            if !sdu.is_empty() || frames == 0 {
                break (sdu, frames);
            }
            // A dropped SDU: return its credits and keep waiting.
            self.grant(frames).await;
        };
        self.grant(frames).await;
        Some(sdu)
    }

    /// Gives the peer `frames` credits back, counting them as granted first.
    async fn grant(&self, frames: u16) {
        if let Some(end) = self
            .conn
            .state
            .coc
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&self.local_cid)
        {
            end.rx_credits = end.rx_credits.saturating_add(frames);
        }
        let mut d = self.local_cid.to_le_bytes().to_vec();
        d.extend_from_slice(&frames.to_le_bytes());
        let id = self.conn.state.sig.id();
        let _ = send_signal(
            &self.conn.host,
            &self.conn.state,
            code::FLOW_CONTROL_CREDIT,
            id,
            &d,
        )
        .await;
    }

    /// Closes the channel.
    pub async fn close(self) -> Result<()> {
        self.conn
            .state
            .coc
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.local_cid);
        let mut d = self.remote_cid.to_le_bytes().to_vec();
        d.extend_from_slice(&self.local_cid.to_le_bytes());
        request(
            &self.conn.host,
            &self.conn.state,
            code::DISCONNECTION_REQ,
            &d,
        )
        .await
        .map(|_| ())
    }
}

/// As peripheral, asks the central for new parameters over the signaling
/// channel. Ok when accepted.
pub(crate) async fn request_param_update(
    host: &Host,
    conn: &Arc<ConnState>,
    p: ParamsRequest,
) -> Result<()> {
    let mut d = Vec::with_capacity(8);
    for v in [p.interval_min, p.interval_max, p.latency, p.timeout] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    match request(host, conn, code::CONN_PARAM_UPDATE_REQ, &d).await? {
        (code::CONN_PARAM_UPDATE_RSP, r) if u16_at(&r, 0) == 0 => Ok(()),
        (code::CONN_PARAM_UPDATE_RSP, _) => Err(Error::Protocol(
            "the central rejected the parameters".into(),
        )),
        _ => Err(Error::Protocol(
            "the central does not take parameter requests".into(),
        )),
    }
}
