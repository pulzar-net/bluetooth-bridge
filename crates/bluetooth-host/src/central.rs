//! The central role: connecting, and the filter accept list.

use std::time::Duration;

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeCreateConnCancel,
    LeExtCreateConn, LeRemoveDeviceFromFilterAcceptList,
};
use bt_hci::param::{AddrKind, BdAddr, Duration as HciDuration, InitiatingPhy, PhyParams};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::address::Address;
use crate::connection::{Connection, ParamsRequest, Phy};
use crate::error::{Error, Result};
use crate::host::Host;

/// How to connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default)]
pub struct ConnectParams {
    /// Scan interval while initiating, ms.
    pub scan_interval_ms: u32,
    /// Scan window while initiating, ms.
    pub scan_window_ms: u32,
    /// Connection parameters to ask for.
    pub params: ParamsRequest,
    /// PHYs to initiate on (Bluetooth 5): `le1m`, `le2m`, `le_coded`.
    pub phys: Vec<Phy>,
    /// Give up after this long, ms.
    pub timeout_ms: u32,
}

impl Default for ConnectParams {
    fn default() -> Self {
        ConnectParams {
            scan_interval_ms: 60,
            scan_window_ms: 30,
            params: ParamsRequest::default(),
            phys: vec![Phy::Le1m],
            timeout_ms: 10_000,
        }
    }
}

fn u625(ms: u32) -> HciDuration<625> {
    HciDuration::from_u16(
        u16::try_from((u64::from(ms) * 1000 / 625).clamp(4, 0x4000)).unwrap_or(0x4000),
    )
}

impl Host {
    /// Connects to a device as central.
    pub async fn connect(&self, peer: Address, p: &ConnectParams) -> Result<Connection> {
        p.params.check()?;
        if p.scan_window_ms > p.scan_interval_ms {
            return Err(Error::InvalidParameter(
                "the scan window must not exceed the interval".into(),
            ));
        }
        let (tx, rx) = oneshot::channel();
        {
            let mut w = self
                .inner
                .connect_waiter
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if w.is_some() {
                return Err(Error::InvalidParameter(
                    "a connection is already being made".into(),
                ));
            }
            *w = Some(tx);
        }
        let r = self.initiate(peer, p).await;
        if let Err(e) = r {
            self.inner
                .connect_waiter
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            return Err(e);
        }
        let mut rx = rx;
        let state =
            match tokio::time::timeout(Duration::from_millis(u64::from(p.timeout_ms)), &mut rx)
                .await
            {
                Ok(Ok(r)) => r?,
                Ok(Err(_)) => return Err(Error::Stopped),
                Err(_) => {
                    let _ = self.inner.hci.exec(&LeCreateConnCancel::new()).await;
                    // The controller answers a cancel with a failed Connection
                    // Complete, or with the connection if it raced the cancel.
                    match tokio::time::timeout(Duration::from_secs(3), rx).await {
                        Ok(Ok(Ok(s))) => s,
                        _ => {
                            self.inner
                                .connect_waiter
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                            return Err(Error::Timeout("the device to accept the connection"));
                        }
                    }
                }
            };
        Ok(Connection::new(self.clone(), state))
    }

    async fn initiate(&self, peer: Address, p: &ConnectParams) -> Result<()> {
        let caps = self.inner.caps();
        let own = AddrKind::new(self.address().hci_type());
        let c = &p.params;
        if caps.extended_advertising() {
            let phy = InitiatingPhy {
                scan_interval: u625(p.scan_interval_ms),
                scan_window: u625(p.scan_window_ms),
                conn_interval_min: HciDuration::from_u16(c.interval_min),
                conn_interval_max: HciDuration::from_u16(c.interval_max),
                max_latency: c.latency,
                supervision_timeout: HciDuration::from_u16(c.timeout),
                min_ce_len: HciDuration::from_u16(0),
                max_ce_len: HciDuration::from_u16(0),
            };
            let want = |x: Phy| p.phys.contains(&x);
            let phys = PhyParams {
                le_1m_phy: (want(Phy::Le1m) || p.phys.is_empty()).then_some(phy),
                le_2m_phy: (want(Phy::Le2m) && caps.phy_2m()).then_some(phy),
                le_coded_phy: (want(Phy::LeCoded) && caps.coded_phy()).then_some(phy),
            };
            self.inner
                .hci
                .exec_async(&LeExtCreateConn::new(
                    false,
                    own,
                    AddrKind::new(peer.hci_type()),
                    BdAddr::new(peer.bytes),
                    phys,
                ))
                .await
        } else {
            self.inner
                .hci
                .exec_async(&LeCreateConn::new(
                    u625(p.scan_interval_ms),
                    u625(p.scan_window_ms),
                    false,
                    AddrKind::new(peer.hci_type()),
                    BdAddr::new(peer.bytes),
                    own,
                    HciDuration::from_u16(c.interval_min),
                    HciDuration::from_u16(c.interval_max),
                    c.latency,
                    HciDuration::from_u16(c.timeout),
                    HciDuration::from_u16(0),
                    HciDuration::from_u16(0),
                ))
                .await
        }
    }

    /// Adds a device to the controller's filter accept list.
    pub async fn accept_list_add(&self, a: Address) -> Result<()> {
        self.inner
            .hci
            .exec(&LeAddDeviceToFilterAcceptList::new(
                AddrKind::new(a.hci_type()),
                BdAddr::new(a.bytes),
            ))
            .await
    }

    /// Removes a device from the filter accept list.
    pub async fn accept_list_remove(&self, a: Address) -> Result<()> {
        self.inner
            .hci
            .exec(&LeRemoveDeviceFromFilterAcceptList::new(
                AddrKind::new(a.hci_type()),
                BdAddr::new(a.bytes),
            ))
            .await
    }

    /// Empties the filter accept list.
    pub async fn accept_list_clear(&self) -> Result<()> {
        self.inner.hci.exec(&LeClearFilterAcceptList::new()).await
    }

    /// Registers an L2CAP credit-based channel server on `spsm`; incoming
    /// channels arrive on the receiver.
    pub fn listen_channel(
        &self,
        spsm: u16,
        mtu: u16,
    ) -> tokio::sync::mpsc::Receiver<crate::l2cap::Channel> {
        crate::l2cap::listen(self, spsm, mtu)
    }
}
