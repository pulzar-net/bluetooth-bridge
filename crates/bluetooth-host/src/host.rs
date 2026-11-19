//! The host: opens a controller, sets it up, and runs the event loop that
//! everything else hangs off.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bt_hci::cmd::controller_baseband::{Reset, SetEventMask};
use bt_hci::cmd::info::{
    ReadBdAddr, ReadLocalSupportedCmds, ReadLocalSupportedFeatures, ReadLocalVersionInformation,
};
use bt_hci::cmd::le::{
    LeReadBufferSize, LeReadFilterAcceptListSize, LeReadLocalSupportedFeatures,
    LeReadMaxAdvDataLength, LeReadMaxDataLength, LeReadNumberOfSupportedAdvSets,
    LeReadResolvingListSize, LeReadSupportedStates, LeSetDefaultPhy, LeSetEventMask,
    LeSetRandomAddr, LeWriteSuggestedDefaultDataLength,
};
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{AllPhys, BdAddr, EventMask, LeEventMask, PhyMask};
use bt_hci::FromHciBytes;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::address::Address;
use crate::connection::{ConnState, Connection, Role};
use crate::controller::Capabilities;
use crate::error::{Error, Result};
use crate::gatt::server::Database;
use crate::hci::{Hci, Reassembly};
use crate::keys::Keys;
use crate::scan::Scanner;
use crate::smp::{Agent, AutoAgent, IoCapability};
use crate::transport::{self, Packet, PacketReader, TransportSpec};
use crate::{advertise, l2cap, scan, smp};

/// How the host presents itself and pairs.
#[derive(Clone)]
pub struct HostConfig {
    /// Where bonds and the local identity are kept; `None` keeps them in memory only.
    pub data_dir: Option<PathBuf>,
    /// The name in the GAP service (and the default advertising name).
    pub device_name: String,
    /// The GAP Appearance value.
    pub appearance: u16,
    /// Our input and output capabilities for pairing.
    pub io_capability: IoCapability,
    /// Answers pairing prompts (passkeys, numeric comparison, OOB data).
    pub agent: Arc<dyn Agent>,
    /// Bond when pairing (store keys so the device stays trusted).
    pub bonding: bool,
    /// Insist on MITM protection (rules out Just Works).
    pub mitm: bool,
    /// Refuse LE legacy pairing (Secure Connections only).
    pub secure_connections_only: bool,
    /// Accept a peer that uses the published debug key (insecure; tests only).
    pub allow_debug_keys: bool,
    /// Use the controller's public address as our identity when it has one;
    /// otherwise (or when false) a static random address kept in `data_dir`.
    pub use_public_address: bool,
    /// Capacity of the event channel; slow readers lose the oldest events.
    pub event_capacity: usize,
}

impl Default for HostConfig {
    fn default() -> Self {
        HostConfig {
            data_dir: None,
            device_name: "bluetooth-bridge".into(),
            appearance: 0,
            io_capability: IoCapability::NoInputNoOutput,
            agent: Arc::new(AutoAgent),
            bonding: true,
            mitm: false,
            secure_connections_only: false,
            allow_debug_keys: false,
            use_public_address: true,
            event_capacity: 1024,
        }
    }
}

/// Something that happened, for the application.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HostEvent {
    /// An advertisement (after duplicate filtering), with its scan response
    /// when there was one.
    Advertisement(Arc<scan::Report>),
    /// A periodic advertising report from a synchronized train.
    PeriodicReport(Arc<scan::PeriodicReport>),
    /// A periodic advertising train was lost.
    PeriodicSyncLost {
        /// The sync handle.
        sync: u16,
    },
    /// A new connection, in either role.
    Connected(Connection),
    /// A connection closed.
    Disconnected {
        /// The connection handle.
        handle: u16,
        /// The peer, as connected.
        peer: Address,
        /// The HCI reason code.
        reason: u8,
    },
    /// An advertising set stopped: its duration ran out, it reached its
    /// event count, or (connectable) someone connected.
    AdvertisingStopped {
        /// The set.
        set: u8,
        /// The connection it made, if any.
        connection: Option<u16>,
    },
    /// A scanner sent a scan request to one of our sets (when asked for).
    ScanRequest {
        /// The set.
        set: u8,
        /// Who asked.
        scanner: Address,
    },
    /// Pairing finished.
    Paired {
        /// The connection.
        handle: u16,
        /// The peer's identity address.
        identity: Address,
        /// Keys were stored.
        bonded: bool,
        /// The resulting security.
        security: crate::connection::Security,
    },
    /// Pairing failed.
    PairingFailed {
        /// The connection.
        handle: u16,
        /// Why.
        reason: String,
    },
    /// A client wrote one of our GATT server's characteristics.
    GattWrite {
        /// The connection.
        handle: u16,
        /// The attribute handle.
        attribute: u16,
        /// The value written (whole, after a long write).
        value: Vec<u8>,
    },
    /// A client changed its notification or indication subscription.
    GattSubscription {
        /// The connection.
        handle: u16,
        /// The characteristic value handle.
        attribute: u16,
        /// Notifications on.
        notify: bool,
        /// Indications on.
        indicate: bool,
    },
    /// The host stopped (the transport closed, or the controller failed).
    Stopped(String),
}

pub(crate) struct Inner {
    pub(crate) hci: Hci,
    pub(crate) caps: OnceLock<Capabilities>,
    pub(crate) config: HostConfig,
    pub(crate) events: broadcast::Sender<HostEvent>,
    pub(crate) conns: Mutex<HashMap<u16, Arc<ConnState>>>,
    pub(crate) scanner: Mutex<Scanner>,
    pub(crate) advertiser: tokio::sync::Mutex<advertise::Advertiser>,
    pub(crate) connect_waiter: Mutex<Option<oneshot::Sender<Result<Arc<ConnState>>>>>,
    pub(crate) sync_waiter: Mutex<Option<oneshot::Sender<Result<u16>>>>,
    pub(crate) keys: Keys,
    pub(crate) gatt: Arc<Database>,
    pub(crate) l2cap_servers: Mutex<HashMap<u16, (u16, mpsc::Sender<l2cap::Channel>)>>,
    pub(crate) local_address: OnceLock<Address>,
    pub(crate) stopped: watch::Sender<Option<String>>,
}

/// A running Bluetooth host on one controller. Cloning it is cheap; every
/// clone drives the same controller.
#[derive(Clone)]
pub struct Host {
    pub(crate) inner: Arc<Inner>,
}

impl Host {
    /// Opens the controller named by `spec`, resets it and reads what it can do.
    pub async fn open(spec: &TransportSpec, config: HostConfig) -> Result<Host> {
        let (reader, writer) = transport::open(spec).await?;
        Self::start(reader, writer, config).await
    }

    /// Starts on an already open transport.
    pub async fn start(
        reader: PacketReader,
        writer: transport::PacketWriter,
        config: HostConfig,
    ) -> Result<Host> {
        let keys = Keys::open(config.data_dir.as_deref())?;
        let gatt = Arc::new(Database::new(&config.device_name, config.appearance));
        let (events, _) = broadcast::channel(config.event_capacity.max(16));
        let inner = Arc::new(Inner {
            hci: Hci::new(writer),
            caps: OnceLock::new(),
            events,
            conns: Mutex::new(HashMap::new()),
            scanner: Mutex::new(Scanner::default()),
            advertiser: tokio::sync::Mutex::new(advertise::Advertiser::default()),
            connect_waiter: Mutex::new(None),
            sync_waiter: Mutex::new(None),
            keys,
            gatt,
            l2cap_servers: Mutex::new(HashMap::new()),
            local_address: OnceLock::new(),
            stopped: watch::channel(None).0,
            config,
        });
        tokio::spawn(read_loop(Arc::downgrade(&inner), reader));
        let host = Host { inner };
        host.init().await?;
        Ok(host)
    }

    async fn init(&self) -> Result<()> {
        let hci = &self.inner.hci;
        hci.command(
            Reset::OPCODE_RAW,
            &crate::hci::encode(&Reset::new()),
            Duration::from_secs(10),
        )
        .await?;
        let version = hci.exec(&ReadLocalVersionInformation::new()).await?;
        let cmds = hci.exec(&ReadLocalSupportedCmds::new()).await?;
        let cmds_raw = cmds.into_inner();
        let lmp = hci.exec(&ReadLocalSupportedFeatures::new()).await?;
        let addr = hci
            .exec(&ReadBdAddr::new())
            .await
            .map(|a| a.raw().try_into().unwrap_or([0; 6]))
            .unwrap_or([0; 6]);
        let mut caps = Capabilities {
            public_address: addr,
            hci_version: version.hci_version.into_inner(),
            hci_subversion: version.hci_subversion,
            lmp_version: version.lmp_version.into_inner(),
            lmp_subversion: version.lmp_subversion,
            manufacturer: version.company_identifier,
            commands: cmds_raw,
            lmp_features: u64::from_le_bytes(lmp.into_inner()),
            le_features: 0,
            le_states: 0,
            le_acl: (27, 1),
            iso: (0, 0),
            max_adv_data: 31,
            adv_sets: 1,
            filter_accept_list_size: 0,
            resolving_list_size: 0,
            max_data_length: (27, 328, 27, 328),
        };
        let m = caps.cmds();

        hci.exec(&SetEventMask::new(
            EventMask::new()
                .enable_disconnection_complete(true)
                .enable_encryption_change_v1(true)
                .enable_read_remote_version_information_complete(true)
                .enable_hardware_error(true)
                .enable_data_buffer_overflow(true)
                .enable_encryption_key_refresh_complete(true)
                .enable_le_meta(true),
        ))
        .await?;

        if m.le_read_local_supported_features() {
            caps.le_features = u64::from_le_bytes(
                hci.exec(&LeReadLocalSupportedFeatures::new())
                    .await?
                    .into_inner(),
            );
        }
        if m.le_read_supported_states() {
            caps.le_states = u64::from_le_bytes(hci.exec(&LeReadSupportedStates::new()).await?);
        }
        let b = hci.exec(&LeReadBufferSize::new()).await?;
        caps.le_acl = (
            b.le_acl_data_packet_length,
            u16::from(b.total_num_le_acl_data_packets),
        );
        if caps.le_acl.1 == 0 {
            // A controller that shares its BR/EDR buffers with LE. bt-hci has
            // no HCI_Read_Buffer_Size yet, so it is sent raw:
            // ACL length (2), SCO length (1), ACL count (2), SCO count (2).
            if let crate::hci::Reply::Complete { status: 0, params } = hci
                .command(0x1005, &[0x05, 0x10, 0x00], crate::hci::COMMAND_TIMEOUT)
                .await?
            {
                if params.len() >= 5 {
                    caps.le_acl = (
                        u16::from_le_bytes([params[0], params[1]]),
                        u16::from_le_bytes([params[3], params[4]]),
                    );
                }
            }
        }
        hci.set_acl_buffers(caps.le_acl.0, caps.le_acl.1);

        if m.le_read_filter_accept_list_size() {
            caps.filter_accept_list_size = hci.exec(&LeReadFilterAcceptListSize::new()).await?;
        }
        if m.le_read_resolving_list_size() {
            caps.resolving_list_size = hci.exec(&LeReadResolvingListSize::new()).await?;
        }
        if caps.data_length_extension() && m.le_read_maximum_data_length() {
            let d = hci.exec(&LeReadMaxDataLength::new()).await?;
            caps.max_data_length = (
                d.supported_max_tx_octets,
                d.supported_max_tx_time,
                d.supported_max_rx_octets,
                d.supported_max_rx_time,
            );
            if m.le_write_suggested_default_data_length() {
                hci.exec(&LeWriteSuggestedDefaultDataLength::new(
                    d.supported_max_tx_octets,
                    d.supported_max_tx_time,
                ))
                .await?;
            }
        }
        if caps.extended_advertising() {
            // Mandatory with the feature; a controller that refuses them
            // keeps the legacy limits.
            if let Ok(n) = hci.exec(&LeReadMaxAdvDataLength::new()).await {
                caps.max_adv_data = n;
            }
            if let Ok(n) = hci.exec(&LeReadNumberOfSupportedAdvSets::new()).await {
                caps.adv_sets = n.max(1);
            }
        }
        if m.le_set_default_phy() && (caps.phy_2m() || caps.coded_phy()) {
            // Let the controller use every PHY it has; peers negotiate down.
            let mut phys = PhyMask::new().set_le_1m_phy(true);
            if caps.phy_2m() {
                phys = phys.set_le_2m_phy(true);
            }
            if caps.coded_phy() {
                phys = phys.set_le_coded_phy(true);
            }
            hci.exec(&LeSetDefaultPhy::new(AllPhys::new(), phys, phys))
                .await?;
        }

        let mut le_mask = LeEventMask::new()
            .enable_le_conn_complete(true)
            .enable_le_adv_report(true)
            .enable_le_conn_update_complete(true)
            .enable_le_read_remote_features_page_0_complete(true)
            .enable_le_long_term_key_request(true)
            .enable_le_remote_conn_parameter_request(true)
            .enable_le_data_length_change(true)
            .enable_le_enhanced_conn_complete_v1(true)
            .enable_le_directed_adv_report(true)
            .enable_le_phy_update_complete(true)
            .enable_le_channel_selection_algorithm(true);
        if caps.extended_scanning() || caps.extended_advertising() {
            le_mask = le_mask
                .enable_le_ext_adv_report(true)
                .enable_le_scan_timeout(true)
                .enable_le_adv_set_terminated(true)
                .enable_le_scan_request_received(true);
        }
        if caps.periodic_advertising() {
            le_mask = le_mask
                .enable_le_periodic_adv_sync_established_v1(true)
                .enable_le_periodic_adv_report_v1(true)
                .enable_le_periodic_adv_sync_lost(true);
        }
        hci.exec(&LeSetEventMask::new(le_mask)).await?;

        // Our identity address.
        let identity = if self.inner.config.use_public_address && addr != [0; 6] {
            Address::public(addr)
        } else {
            let a = self.inner.keys.local_static_address();
            hci.exec(&LeSetRandomAddr::new(BdAddr::new(a.bytes)))
                .await?;
            a
        };
        let _ = self.inner.local_address.set(identity);
        tracing::info!(
            "controller {} ({}), {}, LE features: {}",
            identity,
            caps.manufacturer_name().unwrap_or("unknown manufacturer"),
            caps.version_name().unwrap_or("unknown version"),
            caps.le_feature_names().join(", ")
        );
        let _ = self.inner.caps.set(caps);
        Ok(())
    }

    /// What the controller can do.
    pub fn capabilities(&self) -> &Capabilities {
        // Set before `start` returns.
        self.inner
            .caps
            .get()
            .expect("capabilities are read at start")
    }

    /// Our identity address (public, or the static random one).
    pub fn address(&self) -> Address {
        *self
            .inner
            .local_address
            .get()
            .expect("address is set at start")
    }

    /// Events, from now on. Each call gets its own receiver.
    pub fn events(&self) -> broadcast::Receiver<HostEvent> {
        self.inner.events.subscribe()
    }

    /// Resolves when the host stops, with the reason.
    pub async fn stopped(&self) -> String {
        let mut rx = self.inner.stopped.subscribe();
        loop {
            if let Some(r) = rx.borrow().clone() {
                return r;
            }
            if rx.changed().await.is_err() {
                return "host dropped".into();
            }
        }
    }

    /// The GATT server's database: add services, set values, notify.
    pub fn gatt_server(&self) -> crate::gatt::server::Server {
        crate::gatt::server::Server { host: self.clone() }
    }

    /// Bonds and keys.
    pub fn keys(&self) -> &Keys {
        &self.inner.keys
    }

    /// Open connections.
    pub fn connections(&self) -> Vec<Connection> {
        self.inner
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|s| Connection::new(self.clone(), s.clone()))
            .collect()
    }

    /// A connection by handle.
    pub fn connection(&self, handle: u16) -> Option<Connection> {
        self.inner
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&handle)
            .map(|s| Connection::new(self.clone(), s.clone()))
    }

    pub(crate) fn emit(&self, e: HostEvent) {
        let _ = self.inner.events.send(e);
    }
}

impl Inner {
    pub(crate) fn caps(&self) -> &Capabilities {
        self.caps.get().expect("capabilities are read at start")
    }
}

/// Reads packets until the transport closes, dispatching each.
async fn read_loop(weak: std::sync::Weak<Inner>, mut reader: PacketReader) {
    let mut acl = Reassembly::default();
    let reason = loop {
        let packet = reader.read().await;
        let Some(inner) = weak.upgrade() else { return };
        let host = Host { inner };
        match packet {
            Ok(Packet::Event(bytes)) => {
                if let Some(fatal) = on_event(&host, &bytes) {
                    break fatal;
                }
                // Disconnection Complete: drop any half-received PDU.
                if bytes.first() == Some(&0x05) && bytes.len() >= 6 {
                    acl.close(u16::from_le_bytes([bytes[3], bytes[4]]) & 0x0fff);
                }
            }
            Ok(Packet::Acl(bytes)) => {
                if let Some((handle, pdu)) = acl.push(&bytes) {
                    l2cap::dispatch(&host, handle, pdu);
                }
            }
            Ok(_) => {}
            Err(e) => break format!("transport: {e}"),
        }
    };
    tracing::error!("host stopped: {reason}");
    if let Some(inner) = weak.upgrade() {
        let host = Host { inner };
        host.inner.hci.shutdown();
        let conns: Vec<_> = host
            .inner
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, c)| c)
            .collect();
        for c in conns {
            c.close(0x08);
        }
        host.emit(HostEvent::Stopped(reason.clone()));
        let _ = host.inner.stopped.send(Some(reason));
    }
}

/// Rejects malformed HCI events before they are handed to the parser: each
/// LE Extended Advertising Report must hold its 24 fixed octets and the data
/// its length names.
pub(crate) fn well_formed(bytes: &[u8]) -> bool {
    if bytes.first() != Some(&0x3e) || bytes.get(2) != Some(&0x0d) {
        return true;
    }
    let end = (2 + usize::from(bytes.get(1).copied().unwrap_or(0))).min(bytes.len());
    let Some(&n) = bytes.get(3) else { return false };
    let mut at = 4;
    for _ in 0..n {
        let Some(&len) = bytes.get(at + 23) else {
            return false;
        };
        at += 24 + usize::from(len);
        if at > end {
            return false;
        }
    }
    true
}

/// Handles one event; returns a reason when the host must stop.
fn on_event(host: &Host, bytes: &[u8]) -> Option<String> {
    if !well_formed(bytes) {
        tracing::warn!("dropping a malformed extended advertising report");
        return None;
    }
    let event = match Event::from_hci_bytes(bytes) {
        Ok((e, _)) => e,
        Err(e) => {
            tracing::debug!("unparsed event {:02x?}: {e:?}", bytes.get(..2));
            return None;
        }
    };
    let inner = &host.inner;
    match event {
        Event::CommandComplete(e) => inner.hci.complete(e.cmd_opcode.to_raw(), &e.bytes),
        Event::CommandStatus(e) => inner
            .hci
            .status(e.cmd_opcode.to_raw(), e.status.into_inner()),
        Event::NumberOfCompletedPackets(e) => {
            for c in e.completed_packets {
                if let (Ok(h), Ok(n)) = (c.handle(), c.num_completed_packets()) {
                    inner.hci.completed(h.raw(), n);
                }
            }
        }
        Event::DisconnectionComplete(e) => {
            let handle = e.handle.raw();
            inner.hci.close_handle(handle);
            let conn = inner
                .conns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&handle);
            if let Some(c) = conn {
                let reason = e.reason.into_inner();
                // Keep a bonded client's subscriptions for its next connection.
                let cccd = inner.gatt.connection_closed(handle);
                let identity = c.identity();
                if inner.keys.bond(&identity).is_some() {
                    if let Err(e) = inner.keys.update(&identity, |b| b.cccd = cccd) {
                        tracing::warn!("saving {identity}'s subscriptions: {e}");
                    }
                }
                c.close(reason);
                host.emit(HostEvent::Disconnected {
                    handle,
                    peer: c.peer,
                    reason,
                });
            }
        }
        Event::EncryptionChangeV1(e) => {
            if let Some(c) = host.state(e.handle.raw()) {
                c.encryption_changed(e.status.into_inner(), e.enabled as u8 != 0);
            }
        }
        Event::EncryptionKeyRefreshComplete(e) => {
            if let Some(c) = host.state(e.handle.raw()) {
                c.encryption_changed(e.status.into_inner(), true);
            }
        }
        Event::HardwareError(e) => {
            return Some(format!(
                "controller hardware error {:#04x}",
                e.hardware_code
            ))
        }
        Event::DataBufferOverflow(_) => tracing::warn!("controller reports an ACL buffer overflow"),
        Event::Le(le) => on_le_event(host, le),
        _ => {}
    }
    None
}

fn on_le_event(host: &Host, le: LeEvent<'_>) {
    let inner = &host.inner;
    match le {
        LeEvent::LeAdvertisingReport(e) => {
            for r in e.reports.iter().flatten() {
                scan::on_legacy_report(host, &r);
            }
        }
        LeEvent::LeExtendedAdvertisingReport(e) => {
            for r in e.reports.iter().flatten() {
                scan::on_extended_report(host, &r);
            }
        }
        LeEvent::LeDirectedAdvertisingReport(e) => {
            for r in e.reports {
                scan::on_directed_report(host, r);
            }
        }
        LeEvent::LePeriodicAdvertisingSyncEstablished(e) => {
            let status = e.status.into_inner();
            let result = if status == 0 {
                scan::on_sync_established(host, &e);
                Ok(e.sync_handle.into_inner())
            } else {
                Err(Error::hci(0x2044, status))
            };
            if let Some(w) = inner
                .sync_waiter
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                let _ = w.send(result);
            }
        }
        LeEvent::LePeriodicAdvertisingReport(e) => scan::on_periodic_report(host, &e),
        LeEvent::LePeriodicAdvertisingSyncLost(e) => {
            scan::on_sync_lost(host, e.sync_handle.into_inner());
            host.emit(HostEvent::PeriodicSyncLost {
                sync: e.sync_handle.into_inner(),
            });
        }
        LeEvent::LeConnectionComplete(e) => connection_complete(
            host,
            e.status.into_inner(),
            e.handle.raw(),
            e.role as u8 == 0,
            Address::from_hci(e.peer_addr_kind.into_inner(), raw6(&e.peer_addr)),
            None,
            (
                e.conn_interval.as_u16(),
                e.peripheral_latency,
                e.supervision_timeout.as_u16(),
            ),
        ),
        LeEvent::LeEnhancedConnectionComplete(e) => {
            let peer_rpa = raw6(&e.peer_resolvable_private_addr);
            connection_complete(
                host,
                e.status.into_inner(),
                e.handle.raw(),
                e.role as u8 == 0,
                Address::from_hci(e.peer_addr_kind.into_inner(), raw6(&e.peer_addr)),
                (peer_rpa != [0; 6]).then_some(Address::random(peer_rpa)),
                (
                    e.conn_interval.as_u16(),
                    e.peripheral_latency,
                    e.supervision_timeout.as_u16(),
                ),
            )
        }
        LeEvent::LeConnectionUpdateComplete(e) => {
            if let Some(c) = host.state(e.handle.raw()) {
                c.params_updated(
                    e.status.into_inner(),
                    e.conn_interval.as_u16(),
                    e.peripheral_latency,
                    e.supervision_timeout.as_u16(),
                );
            }
        }
        LeEvent::LeRemoteConnectionParameterRequest(e) => {
            crate::connection::on_remote_param_request(
                host,
                e.handle.raw(),
                e.interval_min.as_u16(),
                e.interval_max.as_u16(),
                e.max_latency,
                e.timeout.as_u16(),
            );
        }
        LeEvent::LeDataLengthChange(e) => {
            if let Some(c) = host.state(e.handle.raw()) {
                c.data_length_changed(
                    e.max_tx_octets,
                    e.max_tx_time,
                    e.max_rx_octets,
                    e.max_rx_time,
                );
            }
        }
        LeEvent::LePhyUpdateComplete(e) => {
            if let Some(c) = host.state(e.handle.raw()) {
                c.phy_updated(e.status.into_inner(), e.tx_phy as u8, e.rx_phy as u8);
            }
        }
        LeEvent::LeReadRemoteFeaturesComplete(e) => {
            if let Some(c) = host.state(e.handle.raw()) {
                c.remote_features(
                    e.status.into_inner(),
                    u64::from_le_bytes(e.le_features.into_inner()),
                );
            }
        }
        LeEvent::LeLongTermKeyRequest(e) => {
            smp::on_ltk_request(
                host,
                e.handle.raw(),
                e.random_number,
                e.encrypted_diversifier,
            );
        }
        LeEvent::LeAdvertisingSetTerminated(e) => {
            let set = e.adv_handle.as_raw();
            let conn = (e.status.into_inner() == 0).then_some(e.handle.raw());
            advertise::on_set_terminated(host, set, conn);
            host.emit(HostEvent::AdvertisingStopped {
                set,
                connection: conn,
            });
        }
        LeEvent::LeScanRequestReceived(e) => host.emit(HostEvent::ScanRequest {
            set: e.adv_handle.as_raw(),
            scanner: Address::from_hci(e.scanner_addr_kind.into_inner(), raw6(&e.scanner_addr)),
        }),
        LeEvent::LeScanTimeout(_) => scan::on_scan_timeout(host),
        _ => {}
    }
}

pub(crate) fn raw6(a: &BdAddr) -> [u8; 6] {
    a.raw().try_into().unwrap_or([0; 6])
}

fn connection_complete(
    host: &Host,
    status: u8,
    handle: u16,
    central: bool,
    peer: Address,
    peer_rpa: Option<Address>,
    params: (u16, u16, u16),
) {
    let inner = &host.inner;
    if status != 0 {
        // A failed or cancelled connect (0x02 after a cancel, 0x3c for an
        // advertising timeout). Only a pending connect() cares.
        if let Some(w) = inner
            .connect_waiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = w.send(Err(Error::hci(0x200d, status)));
        }
        return;
    }
    let role = if central {
        Role::Central
    } else {
        Role::Peripheral
    };
    // The address the peer actually used on the air, for SMP's c1/f5/f6.
    let on_air = peer_rpa.unwrap_or(peer);
    let state = ConnState::spawn(host, handle, role, on_air);
    // The peer's identity: from an IRK for a private address, or a bond.
    if let Some(id) = inner.keys.identity_of(&on_air) {
        state.set_identity(id);
    } else if peer_rpa.is_some() {
        state.set_identity(peer);
    }
    state.set_params(params.0, params.1, params.2);
    if let Some(bond) = inner.keys.bond(&state.identity()) {
        inner.gatt.restore(handle, &bond.cccd);
    }
    inner
        .conns
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(handle, state.clone());
    let conn = Connection::new(host.clone(), state.clone());
    if central {
        if let Some(w) = inner
            .connect_waiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = w.send(Ok(state));
        }
    }
    host.emit(HostEvent::Connected(conn));
}

impl Host {
    pub(crate) fn state(&self, handle: u16) -> Option<Arc<ConnState>> {
        self.inner
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&handle)
            .cloned()
    }
}

/// The opcode of HCI_Reset, for the longer timeout it gets.
trait OpcodeRaw {
    const OPCODE_RAW: u16;
}

impl OpcodeRaw for Reset {
    const OPCODE_RAW: u16 = <Reset as bt_hci::cmd::Cmd>::OPCODE.to_raw();
}
