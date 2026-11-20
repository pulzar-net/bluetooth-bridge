//! The GATT bearer, client side: a mesh reached through a node's Mesh Proxy
//! service rather than on the advertising channels. For a gateway whose
//! radio is busy scanning, or a mesh whose nodes are out of advertising
//! range but within one connection's.
//!
//! Proxy PDUs (SAR and type, [`crate::bearer::proxy_segments`] and
//! [`crate::bearer::ProxyRx`]) go to Mesh Proxy Data In as writes without
//! response and come back as notifications of Data Out. Proxy Configuration
//! messages set which destinations the proxy forwards to us: on connecting,
//! an empty reject list, so it forwards everything.

use std::sync::{Arc, Mutex};

use bluetooth_host::adv::Uuid;
use bluetooth_host::{Address, ConnEvent, ConnectParams, Connection, Host};
use tokio::sync::broadcast;

use crate::bearer::{proxy, proxy_segments, ProxyRx};
use crate::runtime::{ad, Bearer, BoxFuture, Mesh};

/// The Mesh Proxy service and its characteristics (checked against the
/// SIG's assigned numbers in the tests).
pub mod uuid {
    /// Mesh Proxy service.
    pub const SERVICE: u16 = 0x1828;
    /// Mesh Proxy Data In (written by the client).
    pub const DATA_IN: u16 = 0x2add;
    /// Mesh Proxy Data Out (notified to the client).
    pub const DATA_OUT: u16 = 0x2ade;
}

/// A proxy's filter: which destinations it forwards to its client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterType {
    /// Only the addresses listed (the proxy's starting state: nothing).
    Accept,
    /// All but the addresses listed.
    Reject,
}

/// A Proxy Configuration message (opcode and parameters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Config {
    /// Set Filter Type; the list is emptied.
    SetFilterType(FilterType),
    /// Add Addresses to Filter.
    Add(Vec<u16>),
    /// Remove Addresses from Filter.
    Remove(Vec<u16>),
    /// Filter Status, the proxy's answer to each of the others.
    Status {
        /// The filter in force.
        filter: FilterType,
        /// How many addresses it lists.
        list_size: u16,
    },
}

impl Config {
    /// The message's bytes.
    pub fn bytes(&self) -> Vec<u8> {
        let ft = |f: &FilterType| match f {
            FilterType::Accept => 0x00,
            FilterType::Reject => 0x01,
        };
        let addrs = |op: u8, a: &[u16]| {
            let mut v = vec![op];
            for x in a {
                v.extend_from_slice(&x.to_be_bytes());
            }
            v
        };
        match self {
            Config::SetFilterType(f) => vec![0x00, ft(f)],
            Config::Add(a) => addrs(0x01, a),
            Config::Remove(a) => addrs(0x02, a),
            Config::Status { filter, list_size } => {
                let mut v = vec![0x03, ft(filter)];
                v.extend_from_slice(&list_size.to_be_bytes());
                v
            }
        }
    }

    /// Parses one; None for anything malformed or prohibited.
    pub fn parse(d: &[u8]) -> Option<Config> {
        let ft = |b: u8| match b {
            0x00 => Some(FilterType::Accept),
            0x01 => Some(FilterType::Reject),
            _ => None,
        };
        let addrs = |a: &[u8]| -> Option<Vec<u16>> {
            a.len().is_multiple_of(2).then(|| {
                a.chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect()
            })
        };
        let (&op, p) = d.split_first()?;
        match (op, p.len()) {
            (0x00, 1) => Some(Config::SetFilterType(ft(p[0])?)),
            (0x01, _) => Some(Config::Add(addrs(p)?)),
            (0x02, _) => Some(Config::Remove(addrs(p)?)),
            (0x03, 3) => Some(Config::Status {
                filter: ft(p[0])?,
                list_size: u16::from_be_bytes([p[1], p[2]]),
            }),
            _ => None,
        }
    }
}

/// Errors connecting to a proxy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The host failed (connecting, discovery, a write).
    #[error(transparent)]
    Host(#[from] bluetooth_host::Error),
    /// The peer has no Mesh Proxy service, or it lacks a characteristic.
    #[error("no Mesh Proxy service with Data In and Data Out")]
    NotAProxy,
}

/// A connection to a node's Mesh Proxy service, as a [`Bearer`].
pub struct ProxyBearer {
    conn: Connection,
    data_in: u16,
    data_out: u16,
    /// One message's segments at a time, so two messages never interleave.
    lock: tokio::sync::Mutex<()>,
    events: Mutex<Option<broadcast::Receiver<ConnEvent>>>,
}

impl ProxyBearer {
    /// Connects to `peer` (a node advertising the Mesh Proxy service),
    /// exchanges the MTU, and subscribes to Data Out.
    pub async fn connect(host: &Host, peer: Address) -> Result<Arc<Self>, Error> {
        let conn = host.connect(peer, &ConnectParams::default()).await?;
        match Self::on(conn.clone()).await {
            Ok(b) => Ok(b),
            Err(e) => {
                let _ = conn.disconnect().await;
                Err(e)
            }
        }
    }

    /// The bearer on a connection already made.
    pub async fn on(conn: Connection) -> Result<Arc<Self>, Error> {
        // Subscribed before anything is asked, so no notification is missed.
        let events = conn.events();
        let gatt = conn.gatt();
        // A network PDU is at most 29 octets; a larger MTU keeps it in one
        // write. A peer that refuses is still usable, segmented.
        let _ = gatt.exchange_mtu(69).await;
        let service = gatt
            .services_by_uuid(Uuid::Uuid16(uuid::SERVICE))
            .await?
            .into_iter()
            .next()
            .ok_or(Error::NotAProxy)?;
        let chars = gatt.characteristics(&service).await?;
        let find = |u: u16| {
            chars
                .iter()
                .find(|c| c.uuid == Uuid::Uuid16(u))
                .cloned()
                .ok_or(Error::NotAProxy)
        };
        let (data_in, mut data_out) = (find(uuid::DATA_IN)?, find(uuid::DATA_OUT)?);
        data_out.descriptors = gatt.descriptors(&data_out).await?;
        gatt.subscribe(&data_out, true, false).await?;
        Ok(Arc::new(ProxyBearer {
            data_in: data_in.value_handle,
            data_out: data_out.value_handle,
            conn,
            lock: tokio::sync::Mutex::new(()),
            events: Mutex::new(Some(events)),
        }))
    }

    /// The connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Writes one message as Proxy PDUs.
    pub async fn write(&self, kind: u8, msg: &[u8]) -> Result<(), bluetooth_host::Error> {
        let _one = self.lock.lock().await;
        for p in proxy_segments(kind, msg, self.conn.att_mtu()) {
            self.conn
                .gatt()
                .write_without_response(self.data_in, &p)
                .await?;
        }
        Ok(())
    }

    /// Feeds the proxy's messages to `mesh` until the connection closes,
    /// first asking the proxy to forward everything (an empty reject list).
    /// Returns the HCI disconnection reason. `mesh` must have been opened on
    /// this bearer and be provisioned.
    pub async fn run(self: &Arc<Self>, mesh: Mesh) -> u8 {
        let Some(mut events) = self.events.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            tracing::warn!("ProxyBearer::run called twice");
            return 0;
        };
        match mesh.proxy_configuration(&Config::SetFilterType(FilterType::Reject)) {
            Some(m) => {
                if let Err(e) = self.write(proxy::CONFIGURATION, &m).await {
                    tracing::warn!("mesh proxy: setting the filter: {e}");
                }
            }
            None => tracing::warn!("mesh proxy: not provisioned; the proxy forwards nothing"),
        }
        let mut rx = ProxyRx::default();
        loop {
            match events.recv().await {
                Ok(ConnEvent::Notification { handle, value, .. }) if handle == self.data_out => {
                    let Some((kind, msg)) = rx.add(&value) else {
                        continue;
                    };
                    match kind {
                        proxy::NETWORK => mesh.receive(ad::MESSAGE, &msg),
                        proxy::BEACON => mesh.receive(ad::BEACON, &msg),
                        proxy::CONFIGURATION => {
                            if let Some(c) = mesh.open_proxy_configuration(&msg) {
                                tracing::debug!("mesh proxy: {c:?}");
                            }
                        }
                        _ => {}
                    }
                }
                Ok(ConnEvent::Disconnected(reason)) => return reason,
                Err(broadcast::error::RecvError::Closed) => return 0,
                _ => {}
            }
        }
    }
}

impl Bearer for ProxyBearer {
    fn send(&self, ad_type: u8, data: Vec<u8>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let kind = match ad_type {
                ad::MESSAGE => proxy::NETWORK,
                ad::BEACON => proxy::BEACON,
                // PB-ADV is the advertising bearer's; a provisioned proxy
                // has no use for it.
                _ => return,
            };
            if let Err(e) = self.write(kind, &data).await {
                tracing::warn!("mesh proxy: {e}");
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_the_sigs() {
        let name = |u: Option<bluetooth_numbers::Uuid16>| u.map(|u| u.name);
        assert_eq!(
            name(bluetooth_numbers::service(uuid::SERVICE)),
            Some("Mesh Proxy")
        );
        assert_eq!(
            name(bluetooth_numbers::characteristic(uuid::DATA_IN)),
            Some("Mesh Proxy Data In")
        );
        assert_eq!(
            name(bluetooth_numbers::characteristic(uuid::DATA_OUT)),
            Some("Mesh Proxy Data Out")
        );
    }

    #[test]
    fn configuration_messages() {
        for c in [
            Config::SetFilterType(FilterType::Reject),
            Config::SetFilterType(FilterType::Accept),
            Config::Add(vec![0x0001, 0xc000]),
            Config::Remove(vec![]),
            Config::Status {
                filter: FilterType::Accept,
                list_size: 2,
            },
        ] {
            assert_eq!(Config::parse(&c.bytes()), Some(c));
        }
        assert_eq!(
            Config::SetFilterType(FilterType::Reject).bytes(),
            [0x00, 0x01]
        );
        assert_eq!(Config::Add(vec![0x1234]).bytes(), [0x01, 0x12, 0x34]);
        assert_eq!(Config::parse(&[0x00, 0x02]), None, "prohibited filter type");
        assert_eq!(Config::parse(&[0x01, 0x12]), None, "half an address");
        assert_eq!(Config::parse(&[0x03, 0x00, 0x01]), None, "short status");
        assert_eq!(Config::parse(&[0x04]), None);
        assert_eq!(Config::parse(&[]), None);
    }
}
