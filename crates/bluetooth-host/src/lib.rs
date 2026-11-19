//! A Bluetooth host stack over raw HCI.
//!
//! It talks to a controller directly, over the Linux HCI user channel, H4 on
//! a serial port, or H4 over TCP, so the same features work on every board
//! with no BlueZ or D-Bus. HCI commands and events are encoded and decoded by
//! the [`bt_hci`] crate; everything above HCI is here:
//!
//! - controller capability discovery, so features degrade cleanly on old chips;
//! - the observer: passive and active scanning, legacy and extended reports,
//!   the coded PHY, periodic advertising sync, duplicate filtering, and
//!   private addresses resolved to identities;
//! - the broadcaster: legacy, extended and periodic advertising sets;
//! - central and peripheral connections, parameter, PHY and data length updates;
//! - L2CAP signaling and LE credit-based channels;
//! - ATT, a GATT client, and a GATT server built at run time;
//! - SMP: legacy and Secure Connections pairing, every association model,
//!   bonding with a persistent key store, and privacy.
//!
//! ```no_run
//! # async fn demo() -> bluetooth_host::Result<()> {
//! use bluetooth_host::{Host, HostConfig, HostEvent, ScanConfig};
//! let host = Host::open(&"hci0".parse().unwrap(), HostConfig::default()).await?;
//! let mut events = host.events();
//! host.start_scan(ScanConfig::default()).await?;
//! while let Ok(HostEvent::Advertisement(r)) = events.recv().await {
//!     println!("{} {} dBm {:?}", r.device(), r.rssi, r.advertisement().local_name);
//! }
//! # Ok(()) }
//! ```

pub mod address;
pub mod advertise;
pub mod att;
mod central;
pub mod connection;
pub mod controller;
pub mod crypto;
pub mod error;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
pub mod gatt;
mod hci;
mod host;
pub mod keys;
pub mod l2cap;
pub mod probe;
pub mod scan;
pub mod smp;
pub mod transport;

pub use address::{Address, AddressType};
pub use advertise::{AdvertisingParams, PeriodicParams};
pub use bluetooth_adv as adv;
pub use central::ConnectParams;
pub use connection::{ConnEvent, ConnParams, Connection, ParamsRequest, Phy, Role, Security};
pub use controller::Capabilities;
pub use error::{Error, Result};
pub use host::{Host, HostConfig, HostEvent};
pub use scan::{Dedup, PeriodicReport, Report, ScanConfig};
pub use smp::{Agent, AutoAgent, FixedAgent, IoCapability, Method, OobData};
pub use transport::TransportSpec;
