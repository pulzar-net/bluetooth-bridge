//! The observer: scanning (passive and active, legacy and extended, 1M and
//! coded PHY), duplicate filtering, reassembly of fragmented extended
//! reports, resolution of private addresses, and periodic advertising sync.
//!
//! The controller's own duplicate filter is never used: it forgets data
//! changes on some chips and drops RSSI updates on all of them. We filter
//! here, per device and advertising set, with a bounded table.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bluetooth_adv::Advertisement;
use bt_hci::cmd::le::{
    LePeriodicAdvCreateSync, LePeriodicAdvCreateSyncCancel, LePeriodicAdvTerminateSync,
    LeSetExtScanEnable, LeSetExtScanParams, LeSetScanEnable, LeSetScanParams,
};
use bt_hci::param::{
    AddrKind, BdAddr, CteMask, Duration as HciDuration, FilterDuplicates, LeAdvReport,
    LeDirectedAdvertisingReportParam, LeExtAdvReport, LePeriodicAdvCreateSyncOptions, LeScanKind,
    PhyParams, ScanningFilterPolicy, ScanningPhy, SyncHandle,
};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::address::Address;
use crate::connection::Phy;
use crate::error::{Error, Result};
use crate::host::{raw6, Host, HostEvent};

/// How to treat repeats of the same advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Dedup {
    /// Report every advertisement received.
    Off,
    /// Report a device again only when its data changes.
    Changes,
    /// Report when its data changes, and at least every this many
    /// milliseconds while it is heard (so presence and RSSI stay current).
    IntervalMs(u64),
}

/// How to scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default)]
pub struct ScanConfig {
    /// Send scan requests to get scan responses.
    pub active: bool,
    /// Scan interval, ms (2.5 to 10240).
    pub interval_ms: u32,
    /// Scan window, ms (no more than the interval).
    pub window_ms: u32,
    /// Scan on the coded PHY too (long range), when the controller can.
    pub coded: bool,
    /// Only devices on the filter accept list.
    pub filter_accept_list: bool,
    /// Duplicate filtering.
    pub dedup: Dedup,
    /// AD types whose advertisements are reported every time, whatever
    /// `dedup` says: a protocol carried in advertisements, such as Mesh
    /// (`0x29` to `0x2b`), whose retransmissions are identical and must not
    /// be filtered as duplicates.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub always_report: Vec<u8>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            active: false,
            interval_ms: 100,
            window_ms: 100,
            coded: true,
            filter_accept_list: false,
            dedup: Dedup::IntervalMs(10_000),
            always_report: Vec::new(),
        }
    }
}

/// One advertisement, with its scan response when one came.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Report {
    /// The address it was sent from.
    pub address: Address,
    /// The identity behind a private address, when a stored IRK resolves it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Address>,
    /// Received signal strength, dBm.
    pub rssi: i8,
    /// The TX power the advertiser reported in the PDU header (extended
    /// advertising), dBm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_power: Option<i8>,
    /// The primary PHY.
    pub primary_phy: Phy,
    /// The secondary PHY (extended advertising).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_phy: Option<Phy>,
    /// Advertising set id (extended advertising).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<u8>,
    /// Periodic advertising interval, 1.25 ms units, when the set has a train.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub periodic_interval: Option<u16>,
    /// Connectable.
    pub connectable: bool,
    /// Scannable.
    pub scannable: bool,
    /// Directed (at `direct_address`).
    pub directed: bool,
    /// Sent with legacy PDUs.
    pub legacy: bool,
    /// The address a directed advertisement is aimed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_address: Option<Address>,
    /// Advertising data.
    #[serde(serialize_with = "ser_hex")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub data: Vec<u8>,
    /// Scan response data.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_hex_opt"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub scan_response: Option<Vec<u8>>,
    /// The controller could not deliver all of the data.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// When it was received.
    #[serde(serialize_with = "ser_time")]
    #[cfg_attr(feature = "schema", schemars(with = "u64"))]
    pub time: SystemTime,
}

fn ser_hex<S: serde::Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}

fn ser_hex_opt<S: serde::Serializer>(
    v: &Option<Vec<u8>>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match v {
        Some(v) => s.serialize_str(&hex::encode(v)),
        None => s.serialize_none(),
    }
}

fn ser_time<S: serde::Serializer>(t: &SystemTime, s: S) -> std::result::Result<S::Ok, S::Error> {
    let ms = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    s.serialize_u64(u64::try_from(ms).unwrap_or(u64::MAX))
}

impl Report {
    /// The advertising data and scan response, parsed.
    pub fn advertisement(&self) -> Advertisement {
        let mut a = Advertisement::parse(&self.data);
        if let Some(r) = &self.scan_response {
            a.extend(r);
        }
        a
    }

    /// The identity if resolved, else the address.
    pub fn device(&self) -> Address {
        self.identity.unwrap_or(self.address)
    }
}

/// A report from a synchronized periodic advertising train.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PeriodicReport {
    /// The sync handle.
    pub sync: u16,
    /// The advertiser.
    pub address: Address,
    /// Its advertising set.
    pub sid: u8,
    /// RSSI, dBm.
    pub rssi: i8,
    /// TX power, dBm, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_power: Option<i8>,
    /// The data.
    #[serde(serialize_with = "ser_hex")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub data: Vec<u8>,
    /// The controller could not deliver all of it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// What a device's last advertisement (not scan response) said about itself.
#[derive(Clone, Copy)]
struct Props {
    tx_power: Option<i8>,
    primary_phy: Phy,
    secondary_phy: Option<Phy>,
    periodic_interval: Option<u16>,
    connectable: bool,
    scannable: bool,
    directed: bool,
    legacy: bool,
}

struct Seen {
    props: Option<Props>,
    adv: Vec<u8>,
    scan_rsp: Option<Vec<u8>>,
    hash: u64,
    emitted: Option<Instant>,
    last: Instant,
}

struct Train {
    address: Address,
    sid: u8,
    partial: Vec<u8>,
}

/// Scanning state, owned by the host.
#[derive(Default)]
pub(crate) struct Scanner {
    config: Option<ScanConfig>,
    seen: HashMap<(Address, u8), Seen>,
    partial: HashMap<(Address, u8), Vec<u8>>,
    trains: HashMap<u16, Train>,
}

/// Devices remembered for duplicate filtering; past this the oldest go.
const SEEN_LIMIT: usize = 8192;
/// The most extended advertising data one set can carry, with slack.
const MAX_ADV_DATA: usize = 1650;

impl Scanner {
    fn prune(&mut self, now: Instant) {
        if self.seen.len() < SEEN_LIMIT {
            return;
        }
        self.seen
            .retain(|_, s| now.duration_since(s.last) < Duration::from_secs(60));
        if self.seen.len() >= SEEN_LIMIT {
            self.seen.clear();
        }
        if self.partial.len() > 256 {
            self.partial.clear();
        }
    }
}

fn phy(v: u8) -> Phy {
    Phy::from_hci(v)
}

/// What a report carries before duplicate filtering.
struct Incoming {
    address: Address,
    sid: u8,
    rssi: i8,
    tx_power: Option<i8>,
    primary_phy: Phy,
    secondary_phy: Option<Phy>,
    periodic_interval: Option<u16>,
    connectable: bool,
    scannable: bool,
    directed: bool,
    legacy: bool,
    scan_response: bool,
    direct_address: Option<Address>,
    data: Vec<u8>,
    truncated: bool,
}

fn deliver(host: &Host, i: Incoming) {
    let now = Instant::now();
    let identity = host.inner.keys.resolve(&i.address);
    let report = {
        let mut sc = host.inner.scanner.lock().unwrap_or_else(|e| e.into_inner());
        let Some((dedup, always)) = sc.config.as_ref().map(|c| {
            let always = !c.always_report.is_empty()
                && bluetooth_adv::AdStructures::new(&i.data)
                    .flatten()
                    .any(|s| c.always_report.contains(&s.ad_type));
            (c.dedup, always)
        }) else {
            return;
        };
        sc.prune(now);
        let key = (identity.unwrap_or(i.address), i.sid);
        let seen = sc.seen.entry(key).or_insert_with(|| Seen {
            props: None,
            adv: Vec::new(),
            scan_rsp: None,
            hash: 0,
            emitted: None,
            last: now,
        });
        seen.last = now;
        let own = Props {
            tx_power: i.tx_power,
            primary_phy: i.primary_phy,
            secondary_phy: i.secondary_phy,
            periodic_interval: i.periodic_interval,
            connectable: i.connectable,
            scannable: i.scannable,
            directed: i.directed,
            legacy: i.legacy,
        };
        // A scan response says nothing of the advertisement's properties;
        // keep those of the advertisement it answers.
        let props = if i.scan_response {
            seen.scan_rsp = Some(i.data.clone());
            seen.props.unwrap_or(Props {
                scannable: true,
                ..own
            })
        } else {
            seen.adv = i.data.clone();
            seen.props = Some(own);
            own
        };
        let mut h = std::collections::hash_map::DefaultHasher::new();
        seen.adv.hash(&mut h);
        seen.scan_rsp.hash(&mut h);
        let hash = h.finish();
        let changed = hash != seen.hash || seen.emitted.is_none();
        let emit = always
            || match dedup {
                Dedup::Off => true,
                Dedup::Changes => changed,
                Dedup::IntervalMs(ms) => {
                    changed
                        || seen
                            .emitted
                            .is_none_or(|t| now.duration_since(t) >= Duration::from_millis(ms))
                }
            };
        if !emit {
            return;
        }
        seen.hash = hash;
        seen.emitted = Some(now);
        Report {
            address: i.address,
            identity,
            rssi: i.rssi,
            tx_power: props.tx_power,
            primary_phy: props.primary_phy,
            secondary_phy: props.secondary_phy,
            sid: (i.sid != 0xff).then_some(i.sid),
            periodic_interval: props.periodic_interval,
            connectable: props.connectable,
            scannable: props.scannable,
            directed: props.directed,
            legacy: props.legacy,
            direct_address: i.direct_address,
            data: seen.adv.clone(),
            scan_response: seen.scan_rsp.clone(),
            truncated: i.truncated,
            time: SystemTime::now(),
        }
    };
    host.emit(HostEvent::Advertisement(Arc::new(report)));
}

pub(crate) fn on_legacy_report(host: &Host, r: &LeAdvReport<'_>) {
    // Legacy event types: 0 ADV_IND, 1 ADV_DIRECT_IND, 2 ADV_SCAN_IND,
    // 3 ADV_NONCONN_IND, 4 SCAN_RSP.
    let kind = r.event_kind as u8;
    deliver(
        host,
        Incoming {
            address: Address::from_hci(r.addr_kind.into_inner(), raw6(&r.addr)),
            sid: 0xff,
            rssi: r.rssi,
            tx_power: None,
            primary_phy: Phy::Le1m,
            secondary_phy: None,
            periodic_interval: None,
            connectable: kind <= 1,
            scannable: kind == 0 || kind == 2,
            directed: kind == 1,
            legacy: true,
            scan_response: kind == 4,
            direct_address: None,
            data: r.data.to_vec(),
            truncated: false,
        },
    );
}

pub(crate) fn on_directed_report(host: &Host, r: &LeDirectedAdvertisingReportParam) {
    let (Ok(kind), Ok(addr), Ok(rssi), Ok(dkind), Ok(daddr)) = (
        r.addr_kind(),
        r.addr(),
        r.rssi(),
        r.direct_addr_kind(),
        r.direct_addr(),
    ) else {
        return;
    };
    deliver(
        host,
        Incoming {
            address: Address::from_hci(kind.into_inner(), raw6(&addr)),
            sid: 0xff,
            rssi,
            tx_power: None,
            primary_phy: Phy::Le1m,
            secondary_phy: None,
            periodic_interval: None,
            connectable: true,
            scannable: false,
            directed: true,
            legacy: true,
            scan_response: false,
            direct_address: Some(Address::from_hci(dkind.into_inner(), raw6(&daddr))),
            data: Vec::new(),
            truncated: false,
        },
    );
}

pub(crate) fn on_extended_report(host: &Host, r: &LeExtAdvReport<'_>) {
    // Event type bits: 0 connectable, 1 scannable, 2 directed, 3 scan
    // response, 4 legacy, 5-6 data status.
    let ev = u16::from_le_bytes(r.event_kind.into_inner());
    let status = (ev >> 5) & 0b11;
    let address = Address::from_hci(r.addr_kind.into_inner(), raw6(&r.addr));
    let key = (address, r.adv_sid);
    // Reassemble data that arrives in several reports.
    let (data, truncated) = {
        let mut sc = host.inner.scanner.lock().unwrap_or_else(|e| e.into_inner());
        let mut buf = sc.partial.remove(&key).unwrap_or_default();
        if buf.len() + r.data.len() <= MAX_ADV_DATA {
            buf.extend_from_slice(r.data);
        }
        match status {
            0 => (buf, false),
            1 => {
                sc.partial.insert(key, buf);
                return;
            }
            _ => (buf, true),
        }
    };
    let interval = r.adv_interval.as_u16();
    deliver(
        host,
        Incoming {
            address,
            sid: r.adv_sid,
            rssi: r.rssi,
            // 127 means the advertiser did not say.
            tx_power: (r.tx_power != 127).then_some(r.tx_power),
            primary_phy: phy(r.primary_adv_phy as u8),
            secondary_phy: r.secondary_adv_phy.map(|p| phy(p as u8)),
            periodic_interval: (interval != 0).then_some(interval),
            connectable: ev & 0x01 != 0,
            scannable: ev & 0x02 != 0,
            directed: ev & 0x04 != 0,
            legacy: ev & 0x10 != 0,
            scan_response: ev & 0x08 != 0,
            direct_address: (ev & 0x04 != 0)
                .then(|| Address::from_hci(r.direct_addr_kind.into_inner(), raw6(&r.direct_addr))),
            data,
            truncated,
        },
    );
}

pub(crate) fn on_scan_timeout(host: &Host) {
    host.inner
        .scanner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .config = None;
}

pub(crate) fn on_sync_established(
    host: &Host,
    e: &bt_hci::event::le::LePeriodicAdvertisingSyncEstablished,
) {
    host.inner
        .scanner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .trains
        .insert(
            e.sync_handle.into_inner(),
            Train {
                address: Address::from_hci(e.adv_addr_kind.into_inner(), raw6(&e.adv_addr)),
                sid: e.adv_sid,
                partial: Vec::new(),
            },
        );
}

pub(crate) fn on_periodic_report(
    host: &Host,
    e: &bt_hci::event::le::LePeriodicAdvertisingReport<'_>,
) {
    let sync = e.sync_handle.into_inner();
    let status = e.data_status as u8;
    let report = {
        let mut sc = host.inner.scanner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = sc.trains.get_mut(&sync) else {
            return;
        };
        if t.partial.len() + e.data.len() <= MAX_ADV_DATA {
            t.partial.extend_from_slice(e.data);
        }
        if status == 1 {
            return;
        }
        PeriodicReport {
            sync,
            address: t.address,
            sid: t.sid,
            rssi: e.rssi,
            tx_power: (e.tx_power != 127).then_some(e.tx_power),
            data: std::mem::take(&mut t.partial),
            truncated: status == 2,
        }
    };
    host.emit(HostEvent::PeriodicReport(Arc::new(report)));
}

pub(crate) fn on_sync_lost(host: &Host, sync: u16) {
    host.inner
        .scanner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .trains
        .remove(&sync);
}

fn ms_625(ms: u32) -> HciDuration<625> {
    HciDuration::from_u16(
        u16::try_from((u64::from(ms) * 1000 / 625).clamp(4, 0xffff)).unwrap_or(0xffff),
    )
}

impl Host {
    /// Starts scanning (or changes how). Advertisements arrive as
    /// [`HostEvent::Advertisement`].
    pub async fn start_scan(&self, config: ScanConfig) -> Result<()> {
        if config.window_ms > config.interval_ms || config.interval_ms == 0 {
            return Err(Error::InvalidParameter(
                "the scan window must not exceed the interval".into(),
            ));
        }
        let caps = self.inner.caps();
        let hci = &self.inner.hci;
        let _ = self.stop_scan().await;
        let own = AddrKind::new(self.address().hci_type());
        let policy = if config.filter_accept_list {
            ScanningFilterPolicy::BasicFiltered
        } else {
            ScanningFilterPolicy::BasicUnfiltered
        };
        // A controller with extended commands refuses the legacy ones once
        // extended advertising is in use, so extended it is.
        let extended = caps.extended_scanning();
        {
            let mut sc = self.inner.scanner.lock().unwrap_or_else(|e| e.into_inner());
            sc.config = Some(config.clone());
            sc.seen.clear();
            sc.partial.clear();
        }
        let r = if extended {
            let p = ScanningPhy {
                active_scan: config.active,
                scan_interval: ms_625(config.interval_ms),
                scan_window: ms_625(config.window_ms),
            };
            let phys = PhyParams {
                le_1m_phy: Some(p),
                le_2m_phy: None,
                le_coded_phy: (config.coded && caps.coded_phy()).then_some(p),
            };
            hci.exec(&LeSetExtScanParams::new(own, policy, phys))
                .await?;
            hci.exec(&LeSetExtScanEnable::new(
                true,
                FilterDuplicates::Disabled,
                HciDuration::from_u16(0),
                HciDuration::from_u16(0),
            ))
            .await
        } else {
            hci.exec(&LeSetScanParams::new(
                if config.active {
                    LeScanKind::Active
                } else {
                    LeScanKind::Passive
                },
                ms_625(config.interval_ms),
                ms_625(config.window_ms),
                own,
                policy,
            ))
            .await?;
            hci.exec(&LeSetScanEnable::new(true, false)).await
        };
        if r.is_err() {
            self.inner
                .scanner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .config = None;
        }
        r
    }

    /// Stops scanning.
    pub async fn stop_scan(&self) -> Result<()> {
        let was = self
            .inner
            .scanner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .config
            .take();
        let Some(was) = was else { return Ok(()) };
        let caps = self.inner.caps();
        let _ = was;
        if caps.extended_scanning() {
            self.inner
                .hci
                .exec(&LeSetExtScanEnable::new(
                    false,
                    FilterDuplicates::Disabled,
                    HciDuration::from_u16(0),
                    HciDuration::from_u16(0),
                ))
                .await
        } else {
            self.inner
                .hci
                .exec(&LeSetScanEnable::new(false, false))
                .await
        }
    }

    /// Whether scanning is on, and how.
    pub fn scan_config(&self) -> Option<ScanConfig> {
        self.inner
            .scanner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .config
            .clone()
    }

    /// Synchronizes to a periodic advertising train (scanning must be on to
    /// find it). Returns the sync handle; reports arrive as
    /// [`HostEvent::PeriodicReport`].
    pub async fn sync_periodic(
        &self,
        advertiser: Address,
        sid: u8,
        skip: u16,
        timeout_ms: u32,
    ) -> Result<u16> {
        if !self.inner.caps().periodic_advertising() {
            return Err(Error::Unsupported("periodic advertising"));
        }
        let (tx, rx) = oneshot::channel();
        *self
            .inner
            .sync_waiter
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let timeout = u16::try_from((timeout_ms / 10).clamp(10, 0x4000)).unwrap_or(0x4000);
        self.inner
            .hci
            .exec_async(&LePeriodicAdvCreateSync::new(
                LePeriodicAdvCreateSyncOptions::new(),
                sid,
                AddrKind::new(advertiser.hci_type()),
                BdAddr::new(advertiser.bytes),
                skip,
                HciDuration::from_u16(timeout),
                CteMask::new(),
            ))
            .await?;
        let wait = Duration::from_millis(u64::from(timeout_ms).max(2000) * 3);
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(Error::Stopped),
            Err(_) => {
                let _ = self
                    .inner
                    .hci
                    .exec(&LePeriodicAdvCreateSyncCancel::new())
                    .await;
                Err(Error::Timeout("the periodic advertising train"))
            }
        }
    }

    /// Stops following a periodic train.
    pub async fn terminate_sync(&self, sync: u16) -> Result<()> {
        on_sync_lost(self, sync);
        self.inner
            .hci
            .exec(&LePeriodicAdvTerminateSync::new(sync_handle(sync)?))
            .await
    }
}

/// bt-hci's SyncHandle has no constructor; build it from its wire form.
fn sync_handle(h: u16) -> Result<SyncHandle> {
    use bt_hci::FromHciBytes;
    SyncHandle::from_hci_bytes(&h.to_le_bytes())
        .map(|(s, _)| s)
        .map_err(|_| Error::InvalidParameter(format!("sync handle {h}")))
}
