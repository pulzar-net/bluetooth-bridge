//! The broadcaster: advertising sets (legacy, extended, periodic), so the
//! gateway can send packets as well as hear them.
//!
//! A controller with extended advertising is driven only with the extended
//! commands (it refuses to mix the two generations); legacy PDUs are then a
//! property of the set. A Bluetooth 4 controller has the one legacy set.

use std::collections::HashMap;

use bt_hci::cmd::le::{
    LeClearAdvSets, LeRemoveAdvSet, LeSetAdvData, LeSetAdvEnable, LeSetAdvParams,
    LeSetAdvSetRandomAddr, LeSetExtAdvData, LeSetExtAdvEnable, LeSetExtAdvParams,
    LeSetExtScanResponseData, LeSetPeriodicAdvData, LeSetPeriodicAdvEnable, LeSetPeriodicAdvParams,
    LeSetScanResponseData,
};
use bt_hci::param::{
    AddrKind, AdvChannelMap, AdvEventProps, AdvFilterPolicy, AdvHandle, AdvKind, AdvSet, BdAddr,
    Duration as HciDuration, ExtDuration, Operation, PeriodicAdvProps, PhyKind,
};
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::connection::Phy;
use crate::error::{Error, Result};
use crate::host::Host;

/// How a set advertises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default)]
pub struct AdvertisingParams {
    /// Accept connections.
    pub connectable: bool,
    /// Answer scan requests with the scan response.
    pub scannable: bool,
    /// Use legacy PDUs (seen by every scanner, 31 octets of data). `None`
    /// chooses: legacy when the data fits and nothing needs Bluetooth 5.
    pub legacy: Option<bool>,
    /// Advertise directed at one device.
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub directed: Option<Address>,
    /// High duty cycle directed advertising (lasts 1.28 s at most).
    pub high_duty: bool,
    /// Omit our address (extended, non-connectable only).
    pub anonymous: bool,
    /// Put the TX power in the extended header.
    pub include_tx_power: bool,
    /// Minimum interval, ms (20 or more).
    pub interval_min_ms: u32,
    /// Maximum interval, ms.
    pub interval_max_ms: u32,
    /// Primary PHY: `le1m`, or `le_coded` for long range.
    pub primary_phy: Phy,
    /// Secondary PHY (extended).
    pub secondary_phy: Phy,
    /// TX power to ask for, dBm; `None` lets the controller choose.
    pub tx_power: Option<i8>,
    /// Advertising set id (0 to 15), as scanners see it.
    pub sid: u8,
    /// Stop after this long, ms.
    pub duration_ms: Option<u32>,
    /// Stop after this many events (extended).
    pub max_events: Option<u8>,
    /// Only answer scan and connection requests from the filter accept list.
    pub filter_accept_list: bool,
    /// Report scan requests as [`crate::HostEvent::ScanRequest`].
    pub scan_request_notifications: bool,
}

impl Default for AdvertisingParams {
    fn default() -> Self {
        AdvertisingParams {
            connectable: false,
            scannable: false,
            legacy: None,
            directed: None,
            high_duty: false,
            anonymous: false,
            include_tx_power: false,
            interval_min_ms: 100,
            interval_max_ms: 150,
            primary_phy: Phy::Le1m,
            secondary_phy: Phy::Le1m,
            tx_power: None,
            sid: 0,
            duration_ms: None,
            max_events: None,
            filter_accept_list: false,
            scan_request_notifications: false,
        }
    }
}

/// A periodic advertising train on a set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeriodicParams {
    /// Minimum interval, ms (7.5 or more).
    pub interval_min_ms: u32,
    /// Maximum interval, ms.
    pub interval_max_ms: u32,
    /// Put the TX power in each packet.
    pub include_tx_power: bool,
}

impl Default for PeriodicParams {
    fn default() -> Self {
        PeriodicParams {
            interval_min_ms: 100,
            interval_max_ms: 200,
            include_tx_power: false,
        }
    }
}

/// Which sets are running.
#[derive(Default)]
pub(crate) struct Advertiser {
    sets: HashMap<u8, AdvertisingParams>,
}

fn units_625(ms: u32) -> u32 {
    (u64::from(ms) * 1000 / 625).clamp(0x20, 0x00ff_ffff) as u32
}

fn phy_kind(p: Phy) -> PhyKind {
    match p {
        Phy::Le1m => PhyKind::Le1M,
        Phy::Le2m => PhyKind::Le2M,
        Phy::LeCoded => PhyKind::LeCoded,
    }
}

impl Host {
    /// Starts an advertising set; returns its handle. `scan_response` is
    /// sent to active scanners when the set is scannable.
    pub async fn advertise(
        &self,
        params: &AdvertisingParams,
        data: &[u8],
        scan_response: &[u8],
    ) -> Result<u8> {
        if params.interval_min_ms < 20 || params.interval_max_ms < params.interval_min_ms {
            return Err(Error::InvalidParameter("advertising interval".into()));
        }
        if params.connectable && params.anonymous {
            return Err(Error::InvalidParameter(
                "an anonymous set cannot be connectable".into(),
            ));
        }
        let caps = self.inner.caps();
        let mut adv = self.inner.advertiser.lock().await;
        if !caps.extended_advertising() {
            return self
                .advertise_legacy(&mut adv, params, data, scan_response)
                .await;
        }
        let legacy = params.legacy.unwrap_or(
            data.len() <= 31
                && scan_response.len() <= 31
                && params.primary_phy == Phy::Le1m
                && !params.anonymous
                && !params.include_tx_power
                && !(params.connectable && params.scannable && params.directed.is_some()),
        );
        if legacy && (data.len() > 31 || scan_response.len() > 31) {
            return Err(Error::InvalidParameter(
                "legacy advertising data is 31 octets at most".into(),
            ));
        }
        if !legacy && params.connectable && params.scannable {
            return Err(Error::InvalidParameter(
                "an extended set cannot be both connectable and scannable".into(),
            ));
        }
        let max = usize::from(caps.max_adv_data);
        if data.len() > max || scan_response.len() > max {
            return Err(Error::InvalidParameter(format!(
                "this controller takes {max} octets of advertising data"
            )));
        }
        if (params.primary_phy == Phy::LeCoded || params.secondary_phy == Phy::LeCoded)
            && !caps.coded_phy()
        {
            return Err(Error::Unsupported("the coded PHY"));
        }
        if params.secondary_phy == Phy::Le2m && !caps.phy_2m() {
            return Err(Error::Unsupported("the 2M PHY"));
        }
        let handle = (0..caps.adv_sets.max(1))
            .find(|h| !adv.sets.contains_key(h))
            .ok_or(Error::Unsupported(
                "another advertising set (all are in use)",
            ))?;
        let mut props = AdvEventProps::new()
            .set_connectable_adv(params.connectable)
            .set_scannable_adv(
                params.scannable || (legacy && params.connectable && params.directed.is_none()),
            )
            .set_directed_adv(params.directed.is_some())
            .set_high_duty_cycle_directed_connectable_adv(
                params.high_duty && params.directed.is_some(),
            )
            .set_legacy_adv(legacy)
            .set_anonymous_adv(params.anonymous)
            .set_include_tx_power(params.include_tx_power);
        if legacy && !params.connectable && !params.scannable {
            props = props.set_scannable_adv(false);
        }
        let me = self.address();
        let (peer_kind, peer) = match params.directed {
            Some(a) => (AddrKind::new(a.hci_type()), BdAddr::new(a.bytes)),
            None => (AddrKind::PUBLIC, BdAddr::new([0; 6])),
        };
        let filter = if params.filter_accept_list {
            AdvFilterPolicy::FilterConnAndScan
        } else {
            AdvFilterPolicy::Unfiltered
        };
        let h = AdvHandle::new(handle);
        self.inner
            .hci
            .exec(&LeSetExtAdvParams::new(
                h,
                props,
                ExtDuration::from_u32(units_625(params.interval_min_ms)),
                ExtDuration::from_u32(units_625(params.interval_max_ms)),
                AdvChannelMap::ALL,
                AddrKind::new(me.hci_type()),
                peer_kind,
                peer,
                filter,
                params.tx_power.unwrap_or(127),
                phy_kind(params.primary_phy),
                0,
                phy_kind(params.secondary_phy),
                params.sid & 0x0f,
                params.scan_request_notifications,
            ))
            .await?;
        if me.kind == crate::address::AddressType::Random {
            self.inner
                .hci
                .exec(&LeSetAdvSetRandomAddr::new(h, BdAddr::new(me.bytes)))
                .await?;
        }
        self.set_ext_data(handle, data, false).await?;
        if params.scannable || (legacy && !scan_response.is_empty()) {
            self.set_ext_data(handle, scan_response, true).await?;
        }
        let set = AdvSet {
            adv_handle: h,
            duration: HciDuration::from_u16(
                params
                    .duration_ms
                    .map(|d| u16::try_from(d / 10).unwrap_or(0xffff))
                    .unwrap_or(0),
            ),
            max_ext_adv_events: params.max_events.unwrap_or(0),
        };
        self.inner
            .hci
            .exec(&LeSetExtAdvEnable::new(true, &[set]))
            .await?;
        adv.sets.insert(handle, params.clone());
        Ok(handle)
    }

    async fn set_ext_data(&self, handle: u8, data: &[u8], scan_response: bool) -> Result<()> {
        let h = AdvHandle::new(handle);
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(251).collect()
        };
        let n = chunks.len();
        for (i, c) in chunks.into_iter().enumerate() {
            let op = match (i, n) {
                (_, 1) => Operation::Complete,
                (0, _) => Operation::FirstFragment,
                (i, n) if i == n - 1 => Operation::LastFragment,
                _ => Operation::IntermediateFragment,
            };
            if scan_response {
                self.inner
                    .hci
                    .exec(&LeSetExtScanResponseData::new(h, op, false, c))
                    .await?;
            } else {
                self.inner
                    .hci
                    .exec(&LeSetExtAdvData::new(h, op, false, c))
                    .await?;
            }
        }
        Ok(())
    }

    async fn advertise_legacy(
        &self,
        adv: &mut Advertiser,
        params: &AdvertisingParams,
        data: &[u8],
        scan_response: &[u8],
    ) -> Result<u8> {
        if !adv.sets.is_empty() {
            return Err(Error::Unsupported(
                "a second advertising set (Bluetooth 4 controller)",
            ));
        }
        if params.legacy == Some(false)
            || params.anonymous
            || params.include_tx_power
            || params.primary_phy != Phy::Le1m
        {
            return Err(Error::Unsupported("extended advertising"));
        }
        if data.len() > 31 || scan_response.len() > 31 {
            return Err(Error::InvalidParameter(
                "legacy advertising data is 31 octets at most".into(),
            ));
        }
        let kind = match (
            params.connectable,
            params.directed.is_some(),
            params.scannable,
        ) {
            (true, true, _) if params.high_duty => AdvKind::AdvDirectIndHigh,
            (true, true, _) => AdvKind::AdvDirectIndLow,
            (true, false, _) => AdvKind::AdvInd,
            (false, _, true) => AdvKind::AdvScanInd,
            (false, _, false) => AdvKind::AdvNonconnInd,
        };
        let (peer_kind, peer) = match params.directed {
            Some(a) => (AddrKind::new(a.hci_type()), BdAddr::new(a.bytes)),
            None => (AddrKind::PUBLIC, BdAddr::new([0; 6])),
        };
        let to_u16 = |ms: u32| {
            HciDuration::from_u16(u16::try_from(units_625(ms)).unwrap_or(0x4000).min(0x4000))
        };
        self.inner
            .hci
            .exec(&LeSetAdvParams::new(
                to_u16(params.interval_min_ms),
                to_u16(params.interval_max_ms),
                kind,
                AddrKind::new(self.address().hci_type()),
                peer_kind,
                peer,
                AdvChannelMap::ALL,
                if params.filter_accept_list {
                    AdvFilterPolicy::FilterConnAndScan
                } else {
                    AdvFilterPolicy::Unfiltered
                },
            ))
            .await?;
        let mut d = [0u8; 31];
        d[..data.len()].copy_from_slice(data);
        self.inner
            .hci
            .exec(&LeSetAdvData::new(data.len() as u8, d))
            .await?;
        let mut s = [0u8; 31];
        s[..scan_response.len()].copy_from_slice(scan_response);
        self.inner
            .hci
            .exec(&LeSetScanResponseData::new(scan_response.len() as u8, s))
            .await?;
        self.inner.hci.exec(&LeSetAdvEnable::new(true)).await?;
        adv.sets.insert(0, params.clone());
        Ok(0)
    }

    /// Replaces a running set's data (and scan response, when given).
    pub async fn set_advertising_data(
        &self,
        handle: u8,
        data: &[u8],
        scan_response: Option<&[u8]>,
    ) -> Result<()> {
        let adv = self.inner.advertiser.lock().await;
        if !adv.sets.contains_key(&handle) {
            return Err(Error::InvalidParameter(format!(
                "no advertising set {handle}"
            )));
        }
        if !self.inner.caps().extended_advertising() {
            if data.len() > 31 || scan_response.is_some_and(|s| s.len() > 31) {
                return Err(Error::InvalidParameter(
                    "legacy advertising data is 31 octets at most".into(),
                ));
            }
            let mut d = [0u8; 31];
            d[..data.len()].copy_from_slice(data);
            self.inner
                .hci
                .exec(&LeSetAdvData::new(data.len() as u8, d))
                .await?;
            if let Some(sr) = scan_response {
                let mut s = [0u8; 31];
                s[..sr.len()].copy_from_slice(sr);
                self.inner
                    .hci
                    .exec(&LeSetScanResponseData::new(sr.len() as u8, s))
                    .await?;
            }
            return Ok(());
        }
        self.set_ext_data(handle, data, false).await?;
        if let Some(sr) = scan_response {
            self.set_ext_data(handle, sr, true).await?;
        }
        Ok(())
    }

    /// Stops and removes a set.
    pub async fn stop_advertising(&self, handle: u8) -> Result<()> {
        let mut adv = self.inner.advertiser.lock().await;
        if adv.sets.remove(&handle).is_none() {
            return Ok(());
        }
        if !self.inner.caps().extended_advertising() {
            return self.inner.hci.exec(&LeSetAdvEnable::new(false)).await;
        }
        let h = AdvHandle::new(handle);
        let set = AdvSet {
            adv_handle: h,
            duration: HciDuration::from_u16(0),
            max_ext_adv_events: 0,
        };
        // The set may have stopped by itself already.
        let _ = self
            .inner
            .hci
            .exec(&LeSetExtAdvEnable::new(false, &[set]))
            .await;
        self.inner.hci.exec(&LeRemoveAdvSet::new(h)).await
    }

    /// Stops every set.
    pub async fn stop_all_advertising(&self) -> Result<()> {
        let mut adv = self.inner.advertiser.lock().await;
        adv.sets.clear();
        if self.inner.caps().extended_advertising() {
            let _ = self
                .inner
                .hci
                .exec(&LeSetExtAdvEnable::new(false, &[]))
                .await;
            self.inner.hci.exec(&LeClearAdvSets::new()).await
        } else {
            self.inner.hci.exec(&LeSetAdvEnable::new(false)).await
        }
    }

    /// Running sets and their parameters.
    pub async fn advertising_sets(&self) -> Vec<(u8, AdvertisingParams)> {
        let mut v: Vec<_> = self
            .inner
            .advertiser
            .lock()
            .await
            .sets
            .iter()
            .map(|(h, p)| (*h, p.clone()))
            .collect();
        v.sort_by_key(|(h, _)| *h);
        v
    }

    /// Adds a periodic advertising train to a set (which must be extended,
    /// non-connectable and non-scannable) and starts it.
    pub async fn start_periodic(
        &self,
        handle: u8,
        params: &PeriodicParams,
        data: &[u8],
    ) -> Result<()> {
        if !self.inner.caps().periodic_advertising() {
            return Err(Error::Unsupported("periodic advertising"));
        }
        {
            let adv = self.inner.advertiser.lock().await;
            let p = adv
                .sets
                .get(&handle)
                .ok_or_else(|| Error::InvalidParameter(format!("no advertising set {handle}")))?;
            if p.connectable || p.scannable || p.legacy == Some(true) {
                return Err(Error::InvalidParameter(
                    "periodic advertising needs a non-connectable, non-scannable extended set"
                        .into(),
                ));
            }
        }
        let units = |ms: u32| {
            HciDuration::from_u16(
                u16::try_from(u64::from(ms) * 1000 / 1250)
                    .unwrap_or(0xffff)
                    .max(6),
            )
        };
        let h = AdvHandle::new(handle);
        self.inner
            .hci
            .exec(&LeSetPeriodicAdvParams::new(
                h,
                units(params.interval_min_ms),
                units(params.interval_max_ms),
                PeriodicAdvProps::new().include_tx_power(params.include_tx_power),
            ))
            .await?;
        self.set_periodic_data(handle, data).await?;
        self.inner
            .hci
            .exec(&LeSetPeriodicAdvEnable::new(true, h))
            .await
    }

    /// Replaces a periodic train's data.
    pub async fn set_periodic_data(&self, handle: u8, data: &[u8]) -> Result<()> {
        let h = AdvHandle::new(handle);
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(252).collect()
        };
        let n = chunks.len();
        for (i, c) in chunks.into_iter().enumerate() {
            let op = match (i, n) {
                (_, 1) => Operation::Complete,
                (0, _) => Operation::FirstFragment,
                (i, n) if i == n - 1 => Operation::LastFragment,
                _ => Operation::IntermediateFragment,
            };
            self.inner
                .hci
                .exec(&LeSetPeriodicAdvData::new(h, op, c))
                .await?;
        }
        Ok(())
    }

    /// Stops a set's periodic train.
    pub async fn stop_periodic(&self, handle: u8) -> Result<()> {
        self.inner
            .hci
            .exec(&LeSetPeriodicAdvEnable::new(false, AdvHandle::new(handle)))
            .await
    }
}

/// A set stopped on its own (duration, event count, or a connection).
pub(crate) fn on_set_terminated(host: &Host, set: u8, _connection: Option<u16>) {
    let host = host.clone();
    tokio::spawn(async move {
        host.inner.advertiser.lock().await.sets.remove(&set);
    });
}
