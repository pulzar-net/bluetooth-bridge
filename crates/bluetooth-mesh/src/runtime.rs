//! A Mesh node or provisioner on a bearer: PB-ADV provisioning on both
//! sides, the network and transport layers with segmentation and
//! acknowledgments, and the foundation models a provisioner configures
//! (Configuration Server) plus a Generic OnOff Server on the node side.
//!
//! The radio is a [`Bearer`]: [`HostBearer`] advertises and scans through
//! `bluetooth-host`; tests use an in-memory one.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot};

use crate::access::{self, op, Composition, ModelId, Opcode};
use crate::bearer::{Beacon, Generic, PbAdv, TransactionRx};
use crate::crypto::{self, Key};
use crate::network::{self, NetworkKey, NetworkPdu};
use crate::provisioning::{self, Auth, Capabilities, ProvisioningData, Step};
use crate::transport::{self, AccessKey, Lower, Meta, Reassembled, Reassembly};

/// AD types Mesh uses.
pub mod ad {
    /// PB-ADV.
    pub const PB_ADV: u8 = 0x29;
    /// Mesh Message (a Network PDU).
    pub const MESSAGE: u8 = 0x2a;
    /// Mesh Beacon.
    pub const BEACON: u8 = 0x2b;
}

/// A boxed future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Puts one AD structure of Mesh on the air.
pub trait Bearer: Send + Sync {
    /// Sends `data` as one AD structure of `ad_type`.
    fn send(&self, ad_type: u8, data: Vec<u8>) -> BoxFuture<'_, ()>;
}

/// The advertising bearer through `bluetooth-host`: each PDU is sent as a
/// short burst of non-connectable advertising, one at a time.
pub struct HostBearer {
    host: bluetooth_host::Host,
    lock: tokio::sync::Mutex<()>,
}

impl HostBearer {
    /// A bearer on a host (which must be scanning for [`run_host_bearer`] to hear anything).
    pub fn new(host: bluetooth_host::Host) -> Arc<Self> {
        Arc::new(HostBearer {
            host,
            lock: tokio::sync::Mutex::new(()),
        })
    }
}

impl Bearer for HostBearer {
    fn send(&self, ad_type: u8, data: Vec<u8>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _one = self.lock.lock().await;
            let mut adv = vec![(data.len() + 1) as u8, ad_type];
            adv.extend_from_slice(&data);
            let p = bluetooth_host::AdvertisingParams {
                legacy: Some(true),
                interval_min_ms: 20,
                interval_max_ms: 30,
                ..Default::default()
            };
            match self.host.advertise(&p, &adv, &[]).await {
                Ok(set) => {
                    // About three advertising events.
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    let _ = self.host.stop_advertising(set).await;
                }
                Err(e) => tracing::warn!("mesh advertising: {e}"),
            }
        })
    }
}

/// Feeds a host's advertisements to a mesh until the host stops.
pub async fn run_host_bearer(host: bluetooth_host::Host, mesh: Mesh) {
    let mut events = host.events();
    loop {
        match events.recv().await {
            Ok(bluetooth_host::HostEvent::Advertisement(r)) => {
                for s in bluetooth_adv::AdStructures::new(&r.data).flatten() {
                    if matches!(s.ad_type, ad::PB_ADV | ad::MESSAGE | ad::BEACON) {
                        mesh.receive(s.ad_type, s.data);
                    }
                }
            }
            Ok(bluetooth_host::HostEvent::Stopped(_))
            | Err(broadcast::error::RecvError::Closed) => return,
            _ => {}
        }
    }
}

/// A node the provisioner provisioned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecord {
    /// Its Device UUID.
    #[serde(with = "hexa")]
    pub uuid: [u8; 16],
    /// Its primary element's address.
    pub address: u16,
    /// Its elements.
    pub elements: u8,
    /// Its device key.
    #[serde(with = "hexa")]
    pub device_key: Key,
}

/// What a mesh instance keeps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Store {
    /// The IV index.
    pub iv_index: u32,
    /// The next sequence number (persisted ahead in blocks).
    pub seq: u32,
    /// Our primary element address (0 while unprovisioned).
    pub address: u16,
    /// Network keys: index, key.
    pub net_keys: Vec<(u16, HexKey)>,
    /// Application keys: index, bound network key index, key.
    pub app_keys: Vec<(u16, u16, HexKey)>,
    /// Our device key (node role).
    pub device_key: Option<HexKey>,
    /// Provisioned nodes (provisioner role).
    pub nodes: Vec<NodeRecord>,
    /// Model to application key bindings (node role): element, model, app index.
    pub bindings: Vec<(u16, u16, u16)>,
    /// The Generic OnOff Server's state (node role).
    pub onoff: bool,
}

/// A key, kept as hex in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HexKey(#[serde(with = "hexa")] pub Key);

mod hexa {
    pub fn serialize<S: serde::Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        hex::decode(s)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("want 32 hex digits"))
    }
}

/// Sequence numbers reserved per store write.
const SEQ_BLOCK: u32 = 256;
/// Default TTL of what we send.
const TTL: u8 = 7;

/// Something that happened in the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshEvent {
    /// An unprovisioned device's beacon.
    Unprovisioned {
        /// Its UUID.
        uuid: [u8; 16],
        /// OOB information.
        oob_info: u16,
    },
    /// We were provisioned (node role).
    Provisioned {
        /// Our address.
        address: u16,
    },
    /// An access message addressed to us.
    Message {
        /// Source.
        src: u16,
        /// Destination (us, or a group).
        dst: u16,
        /// Opcode.
        opcode: Opcode,
        /// Parameters.
        params: Vec<u8>,
    },
}

/// Mesh errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// No answer in time.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// Provisioning failed with this error code.
    #[error("provisioning failed: error {0:#04x}")]
    Provisioning(u8),
    /// Not possible in this state.
    #[error("{0}")]
    State(&'static str),
}

struct PbLink {
    id: u32,
    /// Next transaction number we send.
    tx: u8,
    /// The transaction acknowledged by the peer last.
    acked: Option<u8>,
    /// Transactions received whole: a repeat is acknowledged again, never
    /// handled twice (numbers are not reused on a link).
    seen: std::collections::HashSet<u8>,
    rx: TransactionRx,
    /// Provisioning PDUs received, for the provisioning task.
    inbox: Vec<Vec<u8>>,
    opened: bool,
    wake: Arc<tokio::sync::Notify>,
}

struct Waiter {
    src: u16,
    opcode: Opcode,
    tx: oneshot::Sender<Vec<u8>>,
}

struct Inner {
    bearer: Arc<dyn Bearer>,
    dir: Option<PathBuf>,
    store: Mutex<Store>,
    reserved: Mutex<u32>,
    uuid: [u8; 16],
    cache: Mutex<network::Cache>,
    reassembly: Mutex<Reassembly>,
    /// Segmented messages awaiting acknowledgment, by (destination, SeqZero):
    /// the union of the blocks acknowledged so far.
    acks: Mutex<HashMap<(u16, u16), tokio::sync::watch::Sender<u32>>>,
    waiters: Mutex<Vec<Waiter>>,
    link: Mutex<Option<PbLink>>,
    device: Mutex<Option<provisioning::Device>>,
    events: broadcast::Sender<MeshEvent>,
}

/// A mesh instance (provisioner, node, or both).
#[derive(Clone)]
pub struct Mesh {
    inner: Arc<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Mesh {
    /// Opens (or creates) a mesh instance with its store in `dir`, and a
    /// Device UUID for when it is a node waiting to be provisioned.
    pub fn open(
        bearer: Arc<dyn Bearer>,
        dir: Option<PathBuf>,
        uuid: [u8; 16],
    ) -> std::io::Result<Mesh> {
        let store = match dir.as_ref().map(|d| d.join("mesh.json")) {
            Some(p) if p.exists() => serde_json::from_slice(&std::fs::read(&p)?)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            _ => Store::default(),
        };
        let reserved = store.seq;
        Ok(Mesh {
            inner: Arc::new(Inner {
                bearer,
                dir,
                store: Mutex::new(store),
                reserved: Mutex::new(reserved),
                uuid,
                cache: Mutex::new(network::Cache::new(1024)),
                reassembly: Mutex::new(Reassembly::default()),
                acks: Mutex::new(HashMap::new()),
                waiters: Mutex::new(Vec::new()),
                link: Mutex::new(None),
                device: Mutex::new(None),
                events: broadcast::channel(256).0,
            }),
        })
    }

    /// Events, from now on.
    pub fn events(&self) -> broadcast::Receiver<MeshEvent> {
        self.inner.events.subscribe()
    }

    /// A copy of the store.
    pub fn store(&self) -> Store {
        lock(&self.inner.store).clone()
    }

    /// Writes the store. The sequence number written is the reserved one,
    /// never the live one, so after a crash a node never reuses a number
    /// its peers' replay protection has already seen.
    fn save(&self) {
        let Some(d) = &self.inner.dir else { return };
        let mut s = lock(&self.inner.store).clone();
        s.seq = s.seq.max(*lock(&self.inner.reserved));
        let r = std::fs::create_dir_all(d).and_then(|_| {
            let tmp = d.join("mesh.json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&s).unwrap_or_default())?;
            std::fs::rename(tmp, d.join("mesh.json"))
        });
        if let Err(e) = r {
            tracing::error!("saving the mesh store: {e}");
        }
    }

    fn next_seq(&self) -> u32 {
        let (seq, write) = {
            let mut s = lock(&self.inner.store);
            let seq = s.seq;
            s.seq += 1;
            let mut r = lock(&self.inner.reserved);
            let write = s.seq >= *r;
            if write {
                *r = s.seq + SEQ_BLOCK;
            }
            (seq, write)
        };
        if write {
            self.save();
        }
        seq
    }

    fn net_keys(&self) -> Vec<NetworkKey> {
        lock(&self.inner.store)
            .net_keys
            .iter()
            .map(|(i, k)| NetworkKey::new(*i, k.0))
            .collect()
    }

    // ------------------------------------------------------------ provisioner

    /// Starts a new network with us as its provisioner at address 0x0001:
    /// a fresh network key (index 0) and application key (index 0).
    pub fn create_network(&self) {
        let mut k = [0u8; 16];
        let mut a = [0u8; 16];
        bluetooth_host::crypto::random_bytes(&mut k);
        bluetooth_host::crypto::random_bytes(&mut a);
        {
            let mut s = lock(&self.inner.store);
            s.net_keys = vec![(0, HexKey(k))];
            s.app_keys = vec![(0, 0, HexKey(a))];
            s.address = 0x0001;
        }
        self.save();
    }

    fn next_address(&self, elements: u8) -> u16 {
        let s = lock(&self.inner.store);
        let mut a = s.address.max(1) + 1;
        for n in &s.nodes {
            a = a.max(n.address + u16::from(n.elements));
        }
        let _ = elements;
        a
    }

    /// Provisions the device with this UUID over PB-ADV; returns its record.
    pub async fn provision(&self, uuid: [u8; 16], auth: Auth) -> Result<NodeRecord, Error> {
        let (net_key, iv_index) = {
            let s = lock(&self.inner.store);
            let k = s
                .net_keys
                .first()
                .ok_or(Error::State("no network: create one first"))?
                .1;
            (k.0, s.iv_index)
        };
        let mut id = [0u8; 4];
        bluetooth_host::crypto::random_bytes(&mut id);
        let link_id = u32::from_be_bytes(id);
        let wake = Arc::new(tokio::sync::Notify::new());
        *lock(&self.inner.link) = Some(PbLink {
            id: link_id,
            tx: 0,
            acked: None,
            seen: std::collections::HashSet::new(),
            rx: TransactionRx::default(),
            inbox: Vec::new(),
            opened: false,
            wake: wake.clone(),
        });
        let r = self
            .provision_on(link_id, uuid, auth, net_key, iv_index, &wake)
            .await;
        for _ in 0..3 {
            self.send_pb(link_id, 0, Generic::LinkClose(u8::from(r.is_err()) * 2))
                .await;
        }
        *lock(&self.inner.link) = None;
        r
    }

    async fn send_pb(&self, link: u32, transaction: u8, pdu: Generic) {
        let p = PbAdv {
            link,
            transaction,
            pdu,
        };
        self.inner.bearer.send(ad::PB_ADV, p.bytes()).await;
    }

    async fn provision_on(
        &self,
        link: u32,
        uuid: [u8; 16],
        auth: Auth,
        net_key: Key,
        iv_index: u32,
        wake: &tokio::sync::Notify,
    ) -> Result<NodeRecord, Error> {
        // Open the link.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            self.send_pb(link, 0, Generic::LinkOpen(uuid)).await;
            if lock(&self.inner.link).as_ref().is_some_and(|l| l.opened) {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                return Err(Error::Timeout("the device to open the link"));
            }
            let _ = tokio::time::timeout(Duration::from_millis(300), wake.notified()).await;
        }
        let address = self.next_address(1);
        let data = ProvisioningData {
            net_key,
            key_index: 0,
            flags: 0,
            iv_index,
            address,
        };
        let (mut p, invite) = provisioning::Provisioner::start(0, auth, data);
        let mut outgoing = vec![invite];
        loop {
            for pdu in outgoing.drain(..) {
                self.send_transaction(&pdu, wake).await?;
            }
            let pdu = self.next_pdu(wake).await?;
            match p.receive(&pdu) {
                Step::Send(v) => outgoing = v,
                Step::Show(_) => {
                    return Err(Error::State(
                        "output and input OOB need a person; use Static or None",
                    ))
                }
                Step::Done { device_key, .. } => {
                    let elements = p.capabilities().map(|c| c.elements).unwrap_or(1);
                    let rec = NodeRecord {
                        uuid,
                        address,
                        elements,
                        device_key,
                    };
                    lock(&self.inner.store).nodes.push(rec.clone());
                    self.save();
                    return Ok(rec);
                }
                Step::Failed { code, send } => {
                    if let Some(f) = send {
                        let _ = self.send_transaction(&f, wake).await;
                    }
                    return Err(Error::Provisioning(code));
                }
            }
        }
    }

    /// Sends one provisioning PDU as a transaction, repeating it until it is acknowledged.
    async fn send_transaction(&self, pdu: &[u8], wake: &tokio::sync::Notify) -> Result<(), Error> {
        let (link, tn) = {
            let mut l = lock(&self.inner.link);
            let l = l.as_mut().ok_or(Error::State("no link"))?;
            let tn = l.tx;
            l.tx = l.tx.wrapping_add(1) & 0x7f | (tn & 0x80);
            (l.id, tn)
        };
        let segments = PbAdv::transaction(link, tn, pdu);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            for s in &segments {
                self.inner.bearer.send(ad::PB_ADV, s.bytes()).await;
            }
            if lock(&self.inner.link)
                .as_ref()
                .is_some_and(|l| l.acked == Some(tn))
            {
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                return Err(Error::Timeout(
                    "a provisioning transaction's acknowledgment",
                ));
            }
            // Wait the whole interval before sending again, however often
            // something else wakes us.
            let resend = tokio::time::Instant::now() + Duration::from_millis(400);
            while tokio::time::Instant::now() < resend {
                let _ = tokio::time::timeout_at(resend, wake.notified()).await;
                if lock(&self.inner.link)
                    .as_ref()
                    .is_some_and(|l| l.acked == Some(tn))
                {
                    return Ok(());
                }
            }
            if lock(&self.inner.link)
                .as_ref()
                .is_some_and(|l| l.acked == Some(tn))
            {
                return Ok(());
            }
        }
    }

    async fn next_pdu(&self, wake: &tokio::sync::Notify) -> Result<Vec<u8>, Error> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(p) = lock(&self.inner.link)
                .as_mut()
                .and_then(|l| (!l.inbox.is_empty()).then(|| l.inbox.remove(0)))
            {
                return Ok(p);
            }
            if tokio::time::timeout_at(deadline, wake.notified())
                .await
                .is_err()
            {
                return Err(Error::Timeout("the device's next provisioning PDU"));
            }
        }
    }

    /// Configures a provisioned node: reads its composition, gives it the
    /// application key, and binds it to every Generic OnOff and Level Server.
    pub async fn configure(&self, node: &NodeRecord) -> Result<Composition, Error> {
        let key = AccessKey::Device(&node.device_key);
        let c = self
            .request(
                node.address,
                key,
                &access::message(op::COMPOSITION_GET, &[0]),
                op::COMPOSITION_STATUS,
            )
            .await?;
        let comp = Composition::parse(&c).ok_or(Error::State("malformed composition data"))?;
        let (app_index, app) = {
            let s = lock(&self.inner.store);
            let (i, _, k) = s
                .app_keys
                .first()
                .copied()
                .ok_or(Error::State("no application key"))?;
            (i, k.0)
        };
        let st = self
            .request(
                node.address,
                key,
                &access::appkey_add(0, app_index, &app),
                op::APPKEY_STATUS,
            )
            .await?;
        if st.first() != Some(&0) {
            return Err(Error::State("the node refused the application key"));
        }
        for (i, e) in comp.elements.iter().enumerate() {
            for m in &e.models {
                if matches!(m, ModelId::Sig(0x1000) | ModelId::Sig(0x1002)) {
                    let addr = node.address + i as u16;
                    let st = self
                        .request(
                            node.address,
                            key,
                            &access::model_app_bind(addr, app_index, *m),
                            op::MODEL_APP_STATUS,
                        )
                        .await?;
                    if st.first() != Some(&0) {
                        return Err(Error::State("the node refused a model binding"));
                    }
                }
            }
        }
        Ok(comp)
    }

    /// Sends an acknowledged access message and waits for the reply's parameters.
    pub async fn request(
        &self,
        dst: u16,
        key: AccessKey<'_>,
        payload: &[u8],
        reply: Opcode,
    ) -> Result<Vec<u8>, Error> {
        for _ in 0..3 {
            let (tx, rx) = oneshot::channel();
            lock(&self.inner.waiters).push(Waiter {
                src: dst,
                opcode: reply,
                tx,
            });
            self.send_access(dst, key, payload).await?;
            if let Ok(Ok(p)) = tokio::time::timeout(Duration::from_secs(5), rx).await {
                return Ok(p);
            }
        }
        Err(Error::Timeout("the node's reply"))
    }

    /// The application key with this index, and its AID.
    pub fn app_key(&self, index: u16) -> Option<(Key, u8)> {
        lock(&self.inner.store)
            .app_keys
            .iter()
            .find(|(i, ..)| *i == index)
            .map(|(_, _, k)| (k.0, crypto::k4(&k.0)))
    }

    /// Sets a Generic OnOff Server and returns its present state.
    pub async fn onoff_set(&self, dst: u16, on: bool, tid: u8) -> Result<bool, Error> {
        let (k, aid) = self.app_key(0).ok_or(Error::State("no application key"))?;
        let p = self
            .request(
                dst,
                AccessKey::App(&k, aid),
                &access::onoff_set(on, tid, true),
                op::ONOFF_STATUS,
            )
            .await?;
        match access::generic_status(op::ONOFF_STATUS, &p) {
            Some(access::GenericStatus::OnOff(present, _)) => Ok(present),
            _ => Err(Error::State("malformed Generic OnOff Status")),
        }
    }

    /// Sends an access message (segmented and acknowledged as needed).
    pub async fn send_access(
        &self,
        dst: u16,
        key: AccessKey<'_>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let (src, iv) = {
            let s = lock(&self.inner.store);
            (s.address, s.iv_index)
        };
        if src == 0 {
            return Err(Error::State("not provisioned"));
        }
        let net = self
            .net_keys()
            .into_iter()
            .next()
            .ok_or(Error::State("no network key"))?;
        let seq = self.next_seq();
        let segmented = payload.len() + 4 > transport::MAX_UNSEGMENTED_ACCESS;
        let upper = transport::encrypt_access(
            key,
            &Meta {
                seq,
                src,
                dst,
                iv_index: iv,
                label: None,
            },
            payload,
            false,
        );
        let aid = match key {
            AccessKey::App(_, aid) => Some(aid),
            AccessKey::Device(_) => None,
        };
        let segs = transport::segment_access(aid, false, seq, &upper, segmented)
            .ok_or(Error::State("message too long"))?;
        // The first segment carries SeqAuth's own number; every other
        // transmission, retransmissions included, takes a new one.
        let mut first = Some(seq);
        let mut send = |which: u32| {
            let mut out = Vec::new();
            for (i, s) in segs.iter().enumerate() {
                if which & (1 << i) == 0 {
                    continue;
                }
                let pdu = NetworkPdu {
                    ctl: false,
                    ttl: TTL,
                    seq: first.take().unwrap_or_else(|| self.next_seq()),
                    src,
                    dst,
                    transport: s.clone(),
                };
                if let Ok(w) = network::encode(&net, iv, &pdu) {
                    out.push(w);
                }
            }
            out
        };
        if !segmented || dst & 0x8000 != 0 {
            for w in send(u32::MAX) {
                self.inner.bearer.send(ad::MESSAGE, w).await;
            }
            return Ok(());
        }
        // Segmented to a unicast address: resend what is not acknowledged.
        let all = (1u32 << segs.len()) - 1;
        let key = (dst, (seq & 0x1fff) as u16);
        let (tx, mut rx) = tokio::sync::watch::channel(0u32);
        lock(&self.inner.acks).insert(key, tx);
        let mut result = Err(Error::Timeout("the segment acknowledgments"));
        for _ in 0..4 {
            let missing = all & !*rx.borrow();
            for w in send(missing) {
                self.inner.bearer.send(ad::MESSAGE, w).await;
            }
            let done =
                tokio::time::timeout(Duration::from_millis(800), rx.wait_for(|b| b & all == all))
                    .await;
            if matches!(done, Ok(Ok(_))) {
                result = Ok(());
                break;
            }
        }
        lock(&self.inner.acks).remove(&key);
        result
    }

    // ------------------------------------------------------------ node

    /// Starts as a node waiting to be provisioned: sends unprovisioned
    /// device beacons until provisioned (then sends nothing).
    pub async fn wait_for_provisioning(&self, caps: Capabilities, static_oob: Option<Key>) {
        *lock(&self.inner.device) = Some(provisioning::Device::new(caps, static_oob));
        while lock(&self.inner.store).address == 0 {
            let mut b = vec![0x00];
            b.extend_from_slice(&self.inner.uuid);
            b.extend_from_slice(&[0, 0]);
            self.inner.bearer.send(ad::BEACON, b).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    fn composition(&self) -> Vec<u8> {
        // CID 0xFFFF (none assigned), PID 0, VID 0, CRPL 32, no features;
        // one element: Configuration Server and Generic OnOff Server.
        let mut d = vec![0x00, 0xff, 0xff, 0, 0, 0, 0, 32, 0, 0, 0];
        d.extend_from_slice(&[0, 0, 2, 0, 0x00, 0x00, 0x00, 0x10]);
        d
    }

    // ------------------------------------------------------------ receiving

    /// Takes one Mesh AD structure heard on the air.
    pub fn receive(&self, ad_type: u8, data: &[u8]) {
        match ad_type {
            ad::BEACON => {
                if let Some(Beacon::Unprovisioned { uuid, oob_info, .. }) = Beacon::parse(data) {
                    let _ = self
                        .inner
                        .events
                        .send(MeshEvent::Unprovisioned { uuid, oob_info });
                }
            }
            ad::PB_ADV => {
                if let Some(p) = PbAdv::parse(data) {
                    self.on_pb_adv(p);
                }
            }
            ad::MESSAGE => self.on_network(data),
            _ => {}
        }
    }

    fn on_pb_adv(&self, p: PbAdv) {
        // The device side: a link opened to our UUID.
        if let Generic::LinkOpen(uuid) = &p.pdu {
            let waiting =
                lock(&self.inner.device).is_some() && lock(&self.inner.store).address == 0;
            if *uuid == self.inner.uuid && waiting {
                let mut l = lock(&self.inner.link);
                if l.as_ref().is_none_or(|l| l.id != p.link) {
                    *l = Some(PbLink {
                        id: p.link,
                        tx: 0x80,
                        acked: None,
                        seen: std::collections::HashSet::new(),
                        rx: TransactionRx::default(),
                        inbox: Vec::new(),
                        opened: true,
                        wake: Arc::new(tokio::sync::Notify::new()),
                    });
                }
                drop(l);
                let me = self.clone();
                let link = p.link;
                tokio::spawn(async move { me.send_pb(link, 0, Generic::LinkAck).await });
            }
            return;
        }
        let mut guard = lock(&self.inner.link);
        let Some(l) = guard.as_mut().filter(|l| l.id == p.link) else {
            return;
        };
        match &p.pdu {
            Generic::LinkAck => {
                l.opened = true;
                l.wake.notify_one();
            }
            Generic::Ack => {
                l.acked = Some(p.transaction);
                l.wake.notify_one();
            }
            Generic::LinkClose(_) => {
                l.opened = false;
                l.wake.notify_one();
            }
            Generic::Start { .. } | Generic::Continuation { .. } => {
                if l.seen.contains(&p.transaction) {
                    // A repeat of what we already have: acknowledge again.
                    let me = self.clone();
                    let (link, tn) = (l.id, p.transaction);
                    tokio::spawn(async move { me.send_pb(link, tn, Generic::Ack).await });
                    return;
                }
                if let Some(pdu) = l.rx.add(&p) {
                    l.seen.insert(p.transaction);
                    let (link, tn) = (l.id, p.transaction);
                    let device_side =
                        lock(&self.inner.device).is_some() && lock(&self.inner.store).address == 0;
                    if device_side {
                        drop(guard);
                        self.device_pdu(link, tn, pdu);
                    } else {
                        l.inbox.push(pdu);
                        l.wake.notify_one();
                        let me = self.clone();
                        tokio::spawn(async move { me.send_pb(link, tn, Generic::Ack).await });
                    }
                }
            }
            Generic::LinkOpen(_) => {}
        }
    }

    /// The device side answers one provisioning PDU.
    fn device_pdu(&self, link: u32, tn: u8, pdu: Vec<u8>) {
        let step = match lock(&self.inner.device).as_mut() {
            Some(d) => d.receive(&pdu),
            None => return,
        };
        let me = self.clone();
        tokio::spawn(async move {
            me.send_pb(link, tn, Generic::Ack).await;
            let wake = lock(&me.inner.link).as_ref().map(|l| l.wake.clone());
            let Some(wake) = wake else { return };
            match step {
                Step::Send(v) => {
                    for p in v {
                        if me.send_transaction(&p, &wake).await.is_err() {
                            return;
                        }
                    }
                }
                Step::Done { device_key, data } => {
                    let _ = me
                        .send_transaction(&[provisioning::pdu::COMPLETE], &wake)
                        .await;
                    if let Some(d) = data {
                        {
                            let mut s = lock(&me.inner.store);
                            s.net_keys = vec![(d.key_index, HexKey(d.net_key))];
                            s.iv_index = d.iv_index;
                            s.address = d.address;
                            s.device_key = Some(HexKey(device_key));
                        }
                        me.save();
                        *lock(&me.inner.device) = None;
                        let _ = me
                            .inner
                            .events
                            .send(MeshEvent::Provisioned { address: d.address });
                    }
                }
                Step::Failed { send, .. } => {
                    if let Some(f) = send {
                        let _ = me.send_transaction(&f, &wake).await;
                    }
                }
                Step::Show(n) => tracing::info!("provisioning: show {n}"),
            }
        });
    }

    fn on_network(&self, data: &[u8]) {
        let (iv, me_addr) = {
            let s = lock(&self.inner.store);
            (s.iv_index, s.address)
        };
        if me_addr == 0 {
            return;
        }
        let keys = self.net_keys();
        let Some((_, iv, pdu)) = network::decode(&keys, iv, data) else {
            return;
        };
        if pdu.src == me_addr || !lock(&self.inner.cache).insert(pdu.src, pdu.seq) {
            return;
        }
        let for_us = pdu.dst == me_addr || pdu.dst == 0xffff || (pdu.dst & 0xc000) == 0xc000;
        if !for_us {
            return;
        }
        let Some(lower) = transport::parse(pdu.ctl, &pdu.transport) else {
            return;
        };
        match lower {
            Lower::Ack {
                seq_zero, block, ..
            } => {
                if let Some(tx) = lock(&self.inner.acks).get(&(pdu.src, seq_zero)) {
                    tx.send_modify(|b| *b |= block);
                }
            }
            Lower::Access { aid, upper } => {
                self.on_upper(pdu.src, pdu.dst, pdu.seq, iv, aid, false, &upper)
            }
            seg @ Lower::Segment { .. } => {
                let Lower::Segment { seq_zero, .. } = seg else {
                    return;
                };
                let r = lock(&self.inner.reassembly).add(pdu.src, &seg);
                let (block, done) = match r {
                    Some(Reassembled::Partial { block }) => (block, None),
                    Some(Reassembled::Complete {
                        aid,
                        big_mic,
                        upper,
                        block,
                    }) => (block, Some((aid, big_mic, upper))),
                    None => return,
                };
                // SeqAuth: the first segment's sequence number.
                let seq_auth = (pdu.seq & !0x1fff) | u32::from(seq_zero);
                let seq_auth = if seq_auth > pdu.seq {
                    seq_auth.wrapping_sub(0x2000)
                } else {
                    seq_auth
                };
                if pdu.dst & 0x8000 == 0 {
                    let me = self.clone();
                    let src = pdu.src;
                    tokio::spawn(async move { me.send_ack(src, seq_zero, block).await });
                }
                if let Some((aid, big_mic, upper)) = done {
                    self.on_upper(
                        pdu.src,
                        pdu.dst,
                        seq_auth & 0x00ff_ffff,
                        iv,
                        aid,
                        big_mic,
                        &upper,
                    );
                }
            }
            Lower::Control { .. } => {}
        }
    }

    async fn send_ack(&self, dst: u16, seq_zero: u16, block: u32) {
        let (src, iv) = {
            let s = lock(&self.inner.store);
            (s.address, s.iv_index)
        };
        let Some(net) = self.net_keys().into_iter().next() else {
            return;
        };
        let pdu = NetworkPdu {
            ctl: true,
            ttl: TTL,
            seq: self.next_seq(),
            src,
            dst,
            transport: transport::ack(seq_zero, block),
        };
        if let Ok(w) = network::encode(&net, iv, &pdu) {
            self.inner.bearer.send(ad::MESSAGE, w).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_upper(
        &self,
        src: u16,
        dst: u16,
        seq: u32,
        iv: u32,
        aid: Option<u8>,
        big_mic: bool,
        upper: &[u8],
    ) {
        let meta = Meta {
            seq,
            src,
            dst,
            iv_index: iv,
            label: None,
        };
        let plain = match aid {
            None => {
                // The device key: ours (node), or the source node's (provisioner).
                let s = lock(&self.inner.store);
                let mut keys: Vec<Key> = s.device_key.iter().map(|k| k.0).collect();
                keys.extend(
                    s.nodes
                        .iter()
                        .filter(|n| n.address == src)
                        .map(|n| n.device_key),
                );
                drop(s);
                keys.iter().find_map(|k| {
                    transport::decrypt_access(AccessKey::Device(k), &meta, upper, big_mic)
                })
            }
            Some(aid) => {
                let keys: Vec<Key> = lock(&self.inner.store)
                    .app_keys
                    .iter()
                    .map(|(_, _, k)| k.0)
                    .filter(|k| crypto::k4(k) == aid)
                    .collect();
                keys.iter().find_map(|k| {
                    transport::decrypt_access(AccessKey::App(k, aid), &meta, upper, big_mic)
                })
            }
        };
        let Some(plain) = plain else { return };
        let Some((opcode, params)) = access::split(&plain) else {
            return;
        };
        let params = params.to_vec();
        {
            let mut w = lock(&self.inner.waiters);
            if let Some(i) = w.iter().position(|x| x.src == src && x.opcode == opcode) {
                let x = w.remove(i);
                let _ = x.tx.send(params);
                return;
            }
        }
        if self.serve(src, aid, opcode, &params) {
            return;
        }
        let _ = self.inner.events.send(MeshEvent::Message {
            src,
            dst,
            opcode,
            params,
        });
    }

    /// The node's servers: Configuration (device key) and Generic OnOff (bound application key).
    fn serve(&self, src: u16, aid: Option<u8>, opcode: Opcode, p: &[u8]) -> bool {
        let Some(dev) = lock(&self.inner.store).device_key.map(|k| k.0) else {
            return false;
        };
        let reply: Option<(Option<u16>, Vec<u8>)> = match (aid, opcode) {
            (None, op::COMPOSITION_GET) => {
                let mut d = vec![0u8];
                d.extend(self.composition()[1..].iter());
                Some((None, access::message(op::COMPOSITION_STATUS, &d)))
            }
            (None, op::APPKEY_ADD) if p.len() == 19 => {
                let v = u32::from(p[0]) | (u32::from(p[1]) << 8) | (u32::from(p[2]) << 16);
                let (net, app) = ((v & 0xfff) as u16, (v >> 12) as u16);
                let mut k = [0u8; 16];
                k.copy_from_slice(&p[3..]);
                {
                    let mut s = lock(&self.inner.store);
                    s.app_keys.retain(|(i, ..)| *i != app);
                    s.app_keys.push((app, net, HexKey(k)));
                }
                self.save();
                let mut st = vec![0u8];
                st.extend_from_slice(&p[..3]);
                Some((None, access::message(op::APPKEY_STATUS, &st)))
            }
            (None, op::MODEL_APP_BIND) if p.len() == 6 => {
                let element = u16::from_le_bytes([p[0], p[1]]);
                let app = u16::from_le_bytes([p[2], p[3]]);
                let model = u16::from_le_bytes([p[4], p[5]]);
                let known = lock(&self.inner.store)
                    .app_keys
                    .iter()
                    .any(|(i, ..)| *i == app);
                let status = if known { 0 } else { 0x03 }; // Invalid AppKey Index
                if known {
                    lock(&self.inner.store).bindings.push((element, model, app));
                    self.save();
                }
                let mut st = vec![status];
                st.extend_from_slice(p);
                Some((None, access::message(op::MODEL_APP_STATUS, &st)))
            }
            (Some(aid), op::ONOFF_GET | op::ONOFF_SET | op::ONOFF_SET_UNACK) => {
                let bound: Vec<u16> = lock(&self.inner.store)
                    .bindings
                    .iter()
                    .filter(|(_, m, _)| *m == 0x1000)
                    .map(|(_, _, a)| *a)
                    .collect();
                let Some(app) = bound
                    .into_iter()
                    .find(|a| self.app_key(*a).is_some_and(|(_, x)| x == aid))
                else {
                    return true;
                };
                if opcode != op::ONOFF_GET {
                    if let Some(&on) = p.first() {
                        lock(&self.inner.store).onoff = on == 1;
                        self.save();
                    }
                }
                if opcode == op::ONOFF_SET_UNACK {
                    return true;
                }
                let on = lock(&self.inner.store).onoff;
                Some((
                    Some(app),
                    access::message(op::ONOFF_STATUS, &[u8::from(on)]),
                ))
            }
            _ => None,
        };
        let Some((app, msg)) = reply else {
            return false;
        };
        let me = self.clone();
        tokio::spawn(async move {
            let r = match app {
                None => me.send_access(src, AccessKey::Device(&dev), &msg).await,
                Some(a) => match me.app_key(a) {
                    Some((k, aid)) => me.send_access(src, AccessKey::App(&k, aid), &msg).await,
                    None => Ok(()),
                },
            };
            if let Err(e) = r {
                tracing::debug!("mesh reply to {src:#06x}: {e}");
            }
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A radio in memory: everything sent reaches every other mesh.
    struct Air {
        meshes: Mutex<Vec<(usize, Mesh)>>,
    }

    struct Radio {
        air: Arc<Air>,
        me: usize,
    }

    impl Bearer for Radio {
        fn send(&self, ad_type: u8, data: Vec<u8>) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                let others: Vec<Mesh> = lock(&self.air.meshes)
                    .iter()
                    .filter(|(i, _)| *i != self.me)
                    .map(|(_, m)| m.clone())
                    .collect();
                for m in others {
                    m.receive(ad_type, &data);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provision_configure_and_control_a_node() {
        let air = Arc::new(Air {
            meshes: Mutex::new(Vec::new()),
        });
        let dir = tempfile::tempdir().unwrap();
        let prov = Mesh::open(
            Arc::new(Radio {
                air: air.clone(),
                me: 0,
            }),
            Some(dir.path().join("p")),
            [0; 16],
        )
        .unwrap();
        let uuid = [0x42; 16];
        let node = Mesh::open(
            Arc::new(Radio {
                air: air.clone(),
                me: 1,
            }),
            Some(dir.path().join("n")),
            uuid,
        )
        .unwrap();
        lock(&air.meshes).extend([(0, prov.clone()), (1, node.clone())]);

        prov.create_network();
        let mut events = prov.events();
        let caps = Capabilities {
            elements: 1,
            algorithms: 1,
            public_key_oob: false,
            static_oob: true,
            output_oob: (0, 0),
            input_oob: (0, 0),
        };
        let n2 = node.clone();
        tokio::spawn(async move { n2.wait_for_provisioning(caps, Some([0x5a; 16])).await });
        // The node's beacon is heard.
        let seen = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(MeshEvent::Unprovisioned { uuid: u, .. }) = events.recv().await {
                    break u;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(seen, uuid);

        let rec = prov
            .provision(uuid, Auth::Static([0x5a; 16]))
            .await
            .unwrap();
        assert_eq!(rec.address, 0x0002);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(node.store().address, 0x0002);
        assert_eq!(node.store().device_key.unwrap().0, rec.device_key);

        let comp = prov.configure(&rec).await.unwrap();
        assert_eq!(
            comp.elements[0].models,
            vec![ModelId::Sig(0), ModelId::Sig(0x1000)]
        );
        assert!(prov.onoff_set(rec.address, true, 1).await.unwrap());
        assert!(node.store().onoff);
        assert!(!prov.onoff_set(rec.address, false, 2).await.unwrap());

        // Both survive a restart from their stores.
        let again = Mesh::open(
            Arc::new(Radio { air, me: 2 }),
            Some(dir.path().join("n")),
            uuid,
        )
        .unwrap();
        assert_eq!(again.store().address, 0x0002);
        assert!(again.store().seq >= node.store().seq);
    }
}
