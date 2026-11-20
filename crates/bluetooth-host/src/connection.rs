//! LE connections: state, parameters, PHY and data length, and the handle
//! applications hold.

use std::collections::HashMap;
use std::sync::atomic::AtomicU16;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bt_hci::cmd::le::{
    LeConnUpdate, LeReadPhy, LeReadRemoteFeatures, LeRemoteConnectionParameterRequestReply,
    LeSetDataLength, LeSetPhy,
};
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::cmd::status::ReadRssi;
use bt_hci::param::{
    AllPhys, ConnHandle, DisconnectReason, Duration as HciDuration, PhyMask, PhyOptions,
};
use serde::Serialize;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::address::Address;
use crate::error::{Error, Result};
use crate::host::Host;
use crate::{att, l2cap, smp};

/// Which end of the connection we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// We initiated it.
    Central,
    /// We advertised and the peer connected.
    Peripheral,
}

/// A PHY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Phy {
    /// LE 1M.
    Le1m,
    /// LE 2M.
    Le2m,
    /// LE Coded (long range).
    LeCoded,
}

impl Phy {
    pub(crate) fn from_hci(v: u8) -> Phy {
        match v {
            2 => Phy::Le2m,
            3 => Phy::LeCoded,
            _ => Phy::Le1m,
        }
    }
}

/// How secure the link is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Security {
    /// The link is encrypted.
    pub encrypted: bool,
    /// The key came from a pairing with MITM protection.
    pub authenticated: bool,
    /// The key came from LE Secure Connections.
    pub secure_connections: bool,
    /// Encryption key size, octets (7 to 16).
    pub key_size: u8,
    /// The keys are stored (a bond).
    pub bonded: bool,
}

impl Security {
    /// LE security mode 1 level: 1 none, 2 unauthenticated encryption,
    /// 3 authenticated, 4 authenticated Secure Connections with a 128-bit key.
    pub fn level(&self) -> u8 {
        match (
            self.encrypted,
            self.authenticated,
            self.secure_connections && self.key_size == 16,
        ) {
            (false, _, _) => 1,
            (true, false, _) => 2,
            (true, true, false) => 3,
            (true, true, true) => 4,
        }
    }
}

/// Connection parameters, in controller units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct ConnParams {
    /// Interval, 1.25 ms units.
    pub interval: u16,
    /// Peripheral latency, connection events.
    pub latency: u16,
    /// Supervision timeout, 10 ms units.
    pub timeout: u16,
}

/// Parameters to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct ParamsRequest {
    /// Minimum interval, 1.25 ms units (6 to 3200).
    pub interval_min: u16,
    /// Maximum interval, 1.25 ms units.
    pub interval_max: u16,
    /// Peripheral latency.
    pub latency: u16,
    /// Supervision timeout, 10 ms units (10 to 3200).
    pub timeout: u16,
}

impl Default for ParamsRequest {
    fn default() -> Self {
        ParamsRequest {
            interval_min: 24,
            interval_max: 40,
            latency: 0,
            timeout: 400,
        }
    }
}

impl ParamsRequest {
    pub(crate) fn check(&self) -> Result<()> {
        let ok = (6..=3200).contains(&self.interval_min)
            && (self.interval_min..=3200).contains(&self.interval_max)
            && self.latency <= 499
            && (10..=3200).contains(&self.timeout)
            // The timeout must exceed (1 + latency) * interval * 2.
            && u32::from(self.timeout) * 8 > (1 + u32::from(self.latency)) * u32::from(self.interval_max) * 2;
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidParameter(format!(
                "connection parameters {self:?}"
            )))
        }
    }
}

/// Data length in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DataLength {
    /// Maximum transmit payload, octets.
    pub tx_octets: u16,
    /// Maximum transmit time, µs.
    pub tx_time: u16,
    /// Maximum receive payload, octets.
    pub rx_octets: u16,
    /// Maximum receive time, µs.
    pub rx_time: u16,
}

/// Something that happened on one connection.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConnEvent {
    /// A notification or indication from the peer's GATT server.
    Notification {
        /// The characteristic value handle.
        handle: u16,
        /// The value.
        value: Vec<u8>,
        /// An indication (already confirmed).
        indication: bool,
    },
    /// The parameters changed.
    ParamsUpdated(ConnParams),
    /// The PHY changed: (tx, rx).
    PhyUpdated(Phy, Phy),
    /// The data length changed.
    DataLengthChanged(DataLength),
    /// Encryption came on, or the key changed.
    SecurityChanged(Security),
    /// The ATT MTU was exchanged.
    MtuExchanged(u16),
    /// The connection closed, with the HCI reason.
    Disconnected(u8),
}

#[derive(Default)]
pub(crate) struct Waiters {
    pub(crate) params: Option<oneshot::Sender<u8>>,
    pub(crate) phy: Option<oneshot::Sender<u8>>,
    pub(crate) features: Option<oneshot::Sender<(u8, u64)>>,
    pub(crate) encryption: Option<oneshot::Sender<u8>>,
}

/// Everything the host keeps about one connection.
pub(crate) struct ConnState {
    pub(crate) handle: u16,
    pub(crate) role: Role,
    /// The peer's address as used on the air (for SMP).
    pub(crate) peer: Address,
    identity: Mutex<Option<Address>>,
    params: Mutex<ConnParams>,
    phy: Mutex<(Phy, Phy)>,
    data_length: Mutex<DataLength>,
    pub(crate) security: watch::Sender<Security>,
    closed: watch::Sender<Option<u8>>,
    pub(crate) in_flight: Arc<AtomicU16>,
    pub(crate) send_lock: tokio::sync::Mutex<()>,
    pub(crate) att_tx: mpsc::Sender<Vec<u8>>,
    pub(crate) smp_tx: mpsc::Sender<Vec<u8>>,
    pub(crate) smp_cmd: mpsc::Sender<smp::Command>,
    pub(crate) sig_tx: mpsc::Sender<Vec<u8>>,
    pub(crate) att: att::Bearer,
    pub(crate) coc: Mutex<HashMap<u16, l2cap::ChannelEnd>>,
    pub(crate) sig: l2cap::Signaling,
    pub(crate) events: broadcast::Sender<ConnEvent>,
    pub(crate) waiters: Mutex<Waiters>,
    pub(crate) remote_features: Mutex<Option<u64>>,
    /// The key of a pairing in progress, for the controller's LTK request.
    pub(crate) pairing_key: smp::PairingKey,
    /// One security procedure (encrypting or pairing) at a time.
    pub(crate) security_op: tokio::sync::Mutex<()>,
}

/// Bound on queued inbound PDUs per fixed channel; a peer that floods past
/// it loses PDUs rather than our memory.
const CHANNEL_DEPTH: usize = 64;

impl ConnState {
    pub(crate) fn spawn(host: &Host, handle: u16, role: Role, peer: Address) -> Arc<ConnState> {
        let (att_tx, att_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (smp_tx, smp_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (smp_cmd, smp_cmd_rx) = mpsc::channel(4);
        let (sig_tx, sig_rx) = mpsc::channel(CHANNEL_DEPTH);
        let in_flight = host.inner.hci.open_handle(handle);
        let bonded_security = Security::default();
        let state = Arc::new(ConnState {
            handle,
            role,
            peer,
            identity: Mutex::new(None),
            params: Mutex::new(ConnParams {
                interval: 0,
                latency: 0,
                timeout: 0,
            }),
            phy: Mutex::new((Phy::Le1m, Phy::Le1m)),
            data_length: Mutex::new(DataLength {
                tx_octets: 27,
                tx_time: 328,
                rx_octets: 27,
                rx_time: 328,
            }),
            security: watch::channel(bonded_security).0,
            closed: watch::channel(None).0,
            in_flight,
            send_lock: tokio::sync::Mutex::new(()),
            att_tx,
            smp_tx,
            smp_cmd,
            sig_tx,
            att: att::Bearer::default(),
            coc: Mutex::new(HashMap::new()),
            sig: l2cap::Signaling::default(),
            events: broadcast::channel(256).0,
            waiters: Mutex::new(Waiters::default()),
            remote_features: Mutex::new(None),
            pairing_key: Mutex::new(None),
            security_op: tokio::sync::Mutex::new(()),
        });
        tokio::spawn(att::run(host.clone(), state.clone(), att_rx));
        tokio::spawn(smp::run(host.clone(), state.clone(), smp_rx, smp_cmd_rx));
        tokio::spawn(l2cap::run_signaling(host.clone(), state.clone(), sig_rx));
        state
    }

    pub(crate) fn identity(&self) -> Address {
        self.identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or(self.peer)
    }

    pub(crate) fn set_identity(&self, a: Address) {
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(a);
    }

    pub(crate) fn set_params(&self, interval: u16, latency: u16, timeout: u16) {
        *self.params.lock().unwrap_or_else(|e| e.into_inner()) = ConnParams {
            interval,
            latency,
            timeout,
        };
    }

    pub(crate) fn waiters(&self) -> std::sync::MutexGuard<'_, Waiters> {
        self.waiters.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.borrow().is_some()
    }

    /// Waits until the connection closes; returns the reason.
    pub(crate) async fn wait_closed(&self) -> u8 {
        let mut rx = self.closed.subscribe();
        loop {
            if let Some(r) = *rx.borrow() {
                return r;
            }
            if rx.changed().await.is_err() {
                return 0x16;
            }
        }
    }

    pub(crate) fn close(&self, reason: u8) {
        let _ = self.closed.send(Some(reason));
        let _ = self.events.send(ConnEvent::Disconnected(reason));
        let mut w = self.waiters();
        *w = Waiters::default();
        drop(w);
        self.att.close();
        self.coc.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub(crate) fn params_updated(&self, status: u8, interval: u16, latency: u16, timeout: u16) {
        if status == 0 {
            self.set_params(interval, latency, timeout);
            let _ = self.events.send(ConnEvent::ParamsUpdated(ConnParams {
                interval,
                latency,
                timeout,
            }));
        }
        if let Some(w) = self.waiters().params.take() {
            let _ = w.send(status);
        }
    }

    pub(crate) fn phy_updated(&self, status: u8, tx: u8, rx: u8) {
        if status == 0 {
            let p = (Phy::from_hci(tx), Phy::from_hci(rx));
            *self.phy.lock().unwrap_or_else(|e| e.into_inner()) = p;
            let _ = self.events.send(ConnEvent::PhyUpdated(p.0, p.1));
        }
        if let Some(w) = self.waiters().phy.take() {
            let _ = w.send(status);
        }
    }

    pub(crate) fn data_length_changed(
        &self,
        tx_octets: u16,
        tx_time: u16,
        rx_octets: u16,
        rx_time: u16,
    ) {
        let d = DataLength {
            tx_octets,
            tx_time,
            rx_octets,
            rx_time,
        };
        *self.data_length.lock().unwrap_or_else(|e| e.into_inner()) = d;
        let _ = self.events.send(ConnEvent::DataLengthChanged(d));
    }

    pub(crate) fn remote_features(&self, status: u8, features: u64) {
        if status == 0 {
            *self
                .remote_features
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(features);
        }
        if let Some(w) = self.waiters().features.take() {
            let _ = w.send((status, features));
        }
    }

    pub(crate) fn encryption_changed(&self, status: u8, on: bool) {
        if status == 0 && on {
            self.security.send_modify(|s| s.encrypted = true);
            let _ = self
                .events
                .send(ConnEvent::SecurityChanged(*self.security.borrow()));
        } else if status == 0 {
            self.security.send_modify(|s| s.encrypted = false);
        }
        if let Some(w) = self.waiters().encryption.take() {
            let _ = w.send(status);
        }
    }

    /// Sends an L2CAP PDU on a channel.
    pub(crate) async fn send(&self, host: &Host, cid: u16, payload: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Disconnected);
        }
        let len = u16::try_from(payload.len())
            .map_err(|_| Error::InvalidParameter("L2CAP PDU over 65535 octets".into()))?;
        let mut pdu = Vec::with_capacity(4 + payload.len());
        pdu.extend_from_slice(&len.to_le_bytes());
        pdu.extend_from_slice(&cid.to_le_bytes());
        pdu.extend_from_slice(payload);
        let _g = self.send_lock.lock().await;
        host.inner
            .hci
            .send_acl(self.handle, &pdu, &self.in_flight)
            .await
    }
}

/// An open LE connection. Cloning it is cheap.
#[derive(Clone)]
pub struct Connection {
    pub(crate) host: Host,
    pub(crate) state: Arc<ConnState>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("handle", &self.state.handle)
            .field("role", &self.state.role)
            .field("peer", &self.state.peer)
            .finish()
    }
}

const PROCEDURE_TIMEOUT: Duration = Duration::from_secs(40);

impl Connection {
    pub(crate) fn new(host: Host, state: Arc<ConnState>) -> Self {
        Connection { host, state }
    }

    /// The HCI connection handle.
    pub fn handle(&self) -> u16 {
        self.state.handle
    }

    /// Our role.
    pub fn role(&self) -> Role {
        self.state.role
    }

    /// The peer's address as it connected (possibly a private address).
    pub fn peer(&self) -> Address {
        self.state.peer
    }

    /// The peer's identity: its identity address once resolved (from a bond's
    /// IRK, or from pairing), otherwise the address it connected with.
    pub fn identity(&self) -> Address {
        self.state.identity()
    }

    /// Current connection parameters.
    pub fn params(&self) -> ConnParams {
        *self.state.params.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current PHYs (tx, rx).
    pub fn phy(&self) -> (Phy, Phy) {
        *self.state.phy.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current data length.
    pub fn data_length(&self) -> DataLength {
        *self
            .state
            .data_length
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Current security.
    pub fn security(&self) -> Security {
        *self.state.security.borrow()
    }

    /// The ATT MTU in use.
    pub fn att_mtu(&self) -> u16 {
        self.state.att.mtu()
    }

    /// Events on this connection, from now on.
    pub fn events(&self) -> broadcast::Receiver<ConnEvent> {
        self.state.events.subscribe()
    }

    /// Whether it is still open.
    pub fn is_connected(&self) -> bool {
        !self.state.is_closed()
    }

    /// Waits until the connection closes; returns the HCI reason.
    pub async fn disconnected(&self) -> u8 {
        self.state.wait_closed().await
    }

    /// Closes the connection (reason: Remote User Terminated Connection).
    pub async fn disconnect(&self) -> Result<()> {
        if self.state.is_closed() {
            return Ok(());
        }
        self.host
            .inner
            .hci
            .exec_async(&Disconnect::new(
                ConnHandle::new(self.state.handle),
                DisconnectReason::RemoteUserTerminatedConn,
            ))
            .await?;
        tokio::time::timeout(Duration::from_secs(10), self.state.wait_closed())
            .await
            .map(|_| ())
            .map_err(|_| Error::Timeout("disconnection"))
    }

    /// Asks for new connection parameters. As central the controller
    /// negotiates them; as peripheral we ask the central over L2CAP.
    pub async fn update_params(&self, p: ParamsRequest) -> Result<ConnParams> {
        p.check()?;
        match self.state.role {
            Role::Central => {
                let (tx, rx) = oneshot::channel();
                self.state.waiters().params = Some(tx);
                self.host
                    .inner
                    .hci
                    .exec_async(&LeConnUpdate::new(
                        ConnHandle::new(self.state.handle),
                        HciDuration::from_u16(p.interval_min),
                        HciDuration::from_u16(p.interval_max),
                        p.latency,
                        HciDuration::from_u16(p.timeout),
                        HciDuration::from_u16(0),
                        HciDuration::from_u16(0),
                    ))
                    .await?;
                match tokio::time::timeout(PROCEDURE_TIMEOUT, rx).await {
                    Ok(Ok(0)) => Ok(self.params()),
                    Ok(Ok(s)) => Err(Error::hci(0x2013, s)),
                    Ok(Err(_)) => Err(Error::Disconnected),
                    Err(_) => Err(Error::Timeout("connection update")),
                }
            }
            Role::Peripheral => {
                let mut rx = self.state.events.subscribe();
                l2cap::request_param_update(&self.host, &self.state, p).await?;
                // Accepted: the central now runs the update.
                let deadline = tokio::time::Instant::now() + PROCEDURE_TIMEOUT;
                loop {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Ok(ConnEvent::ParamsUpdated(c))) => return Ok(c),
                        Ok(Ok(ConnEvent::Disconnected(_)))
                        | Ok(Err(broadcast::error::RecvError::Closed)) => {
                            return Err(Error::Disconnected)
                        }
                        Ok(_) => {}
                        Err(_) => return Ok(self.params()),
                    }
                }
            }
        }
    }

    /// Asks for PHYs. Each set lists the PHYs we accept in that direction;
    /// `coded_s8` prefers the S=8 coding on the coded PHY (longer range).
    pub async fn set_phy(&self, tx: &[Phy], rx: &[Phy], coded_s8: bool) -> Result<(Phy, Phy)> {
        if !self.host.inner.caps().phy_update() {
            return Err(Error::Unsupported("PHY update (no 2M or coded PHY)"));
        }
        let mask = |s: &[Phy]| {
            let mut m = PhyMask::new();
            for p in s {
                m = match p {
                    Phy::Le1m => m.set_le_1m_phy(true),
                    Phy::Le2m => m.set_le_2m_phy(true),
                    Phy::LeCoded => m.set_le_coded_phy(true),
                };
            }
            m
        };
        let options = if coded_s8 {
            PhyOptions::S8CodingPreferred
        } else {
            PhyOptions::NoPreferredCoding
        };
        let (txw, rxw) = oneshot::channel();
        self.state.waiters().phy = Some(txw);
        self.host
            .inner
            .hci
            .exec_async(&LeSetPhy::new(
                ConnHandle::new(self.state.handle),
                AllPhys::new(),
                mask(tx),
                mask(rx),
                options,
            ))
            .await?;
        match tokio::time::timeout(PROCEDURE_TIMEOUT, rxw).await {
            Ok(Ok(0)) => Ok(self.phy()),
            Ok(Ok(s)) => Err(Error::hci(0x2032, s)),
            Ok(Err(_)) => Err(Error::Disconnected),
            Err(_) => Err(Error::Timeout("PHY update")),
        }
    }

    /// Reads the PHYs in use from the controller.
    pub async fn read_phy(&self) -> Result<(Phy, Phy)> {
        if !self.host.inner.caps().cmds().le_read_phy() {
            return Ok(self.phy());
        }
        let r = self
            .host
            .inner
            .hci
            .exec(&LeReadPhy::new(ConnHandle::new(self.state.handle)))
            .await?;
        let p = (Phy::from_hci(r.tx_phy as u8), Phy::from_hci(r.rx_phy as u8));
        *self.state.phy.lock().unwrap_or_else(|e| e.into_inner()) = p;
        Ok(p)
    }

    /// Asks for a data length (octets 27 to 251, time 328 to 17040 µs).
    pub async fn set_data_length(&self, tx_octets: u16, tx_time: u16) -> Result<()> {
        if !self.host.inner.caps().data_length_extension() {
            return Err(Error::Unsupported("data length extension"));
        }
        if !(27..=251).contains(&tx_octets) || !(328..=17040).contains(&tx_time) {
            return Err(Error::InvalidParameter(format!(
                "data length {tx_octets} octets, {tx_time} µs"
            )));
        }
        self.host
            .inner
            .hci
            .exec(&LeSetDataLength::new(
                ConnHandle::new(self.state.handle),
                tx_octets,
                tx_time,
            ))
            .await?;
        Ok(())
    }

    /// The signal strength of the link, dBm.
    pub async fn read_rssi(&self) -> Result<i8> {
        let r = self
            .host
            .inner
            .hci
            .exec(&ReadRssi::new(ConnHandle::new(self.state.handle)))
            .await?;
        Ok(r.rssi)
    }

    /// The peer's LE features (read once, then remembered).
    pub async fn remote_features(&self) -> Result<u64> {
        if let Some(f) = *self
            .state
            .remote_features
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return Ok(f);
        }
        let (tx, rx) = oneshot::channel();
        self.state.waiters().features = Some(tx);
        self.host
            .inner
            .hci
            .exec_async(&LeReadRemoteFeatures::new(ConnHandle::new(
                self.state.handle,
            )))
            .await?;
        match tokio::time::timeout(PROCEDURE_TIMEOUT, rx).await {
            Ok(Ok((0, f))) => Ok(f),
            Ok(Ok((s, _))) => Err(Error::hci(0x2016, s)),
            Ok(Err(_)) => Err(Error::Disconnected),
            Err(_) => Err(Error::Timeout("remote features")),
        }
    }

    /// The GATT client for the peer's server.
    pub fn gatt(&self) -> crate::gatt::client::Client {
        crate::gatt::client::Client { conn: self.clone() }
    }

    /// Pairs (and bonds, per the host's configuration). As peripheral this
    /// sends a Security Request and the central decides.
    pub async fn pair(&self) -> Result<Security> {
        smp::pair(self).await
    }

    /// Encrypts the link with a bond's stored key, pairing if there is none.
    pub async fn secure(&self) -> Result<Security> {
        smp::secure(self).await
    }

    /// Opens an LE credit-based channel to the peer's `spsm`.
    pub async fn open_channel(&self, spsm: u16, mtu: u16) -> Result<l2cap::Channel> {
        l2cap::connect(self, spsm, mtu).await
    }
}

/// The controller asks whether we accept the peer's parameter request:
/// accept anything valid (the central decides what the link can take).
pub(crate) fn on_remote_param_request(
    host: &Host,
    handle: u16,
    min: u16,
    max: u16,
    latency: u16,
    timeout: u16,
) {
    let host = host.clone();
    tokio::spawn(async move {
        let r = host
            .inner
            .hci
            .exec(&LeRemoteConnectionParameterRequestReply::new(
                ConnHandle::new(handle),
                HciDuration::from_u16(min),
                HciDuration::from_u16(max),
                latency,
                HciDuration::from_u16(timeout),
                HciDuration::from_u16(0),
                HciDuration::from_u16(0),
            ))
            .await;
        if let Err(e) = r {
            tracing::warn!("could not accept connection parameters on {handle:#05x}: {e}");
        }
    });
}
