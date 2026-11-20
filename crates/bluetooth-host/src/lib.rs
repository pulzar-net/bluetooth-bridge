#![doc = include_str!("../README.md")]

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
