//! A standalone Bluetooth LE to MQTT bridge on the [`bluetooth_host`] stack.
//!
//! Advertisements go out parsed (every AD type, beacon formats decoded),
//! decoded sensor readings get Home Assistant discovery, and every GATT,
//! pairing and advertising operation is a request on MQTT. See
//! [`bridge`] for the topics.

pub mod bridge;
pub mod config;
pub mod ha;
pub mod mqtt;

pub use bridge::run;
pub use config::Config;
