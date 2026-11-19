//! Naming a controller without starting a host: reset it and read who made
//! it and what it can do. Bounded and harmless: it sends only Reset and
//! read commands, and closes the transport when done.

use std::time::Duration;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::host::{Host, HostConfig};
use crate::transport::TransportSpec;

/// What a probe found.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    /// The controller's public address, if it has one.
    pub address: Option<String>,
    /// Manufacturer company identifier.
    pub manufacturer: u16,
    /// Its name, from the assigned numbers.
    pub manufacturer_name: Option<&'static str>,
    /// HCI version number.
    pub hci_version: u8,
    /// The Core Specification that version is.
    pub version_name: Option<&'static str>,
    /// LMP/LL subversion (identifies the firmware build).
    pub lmp_subversion: u16,
    /// LE features by name.
    pub le_features: Vec<&'static str>,
    /// Advertising sets.
    pub adv_sets: u8,
}

/// Probes the controller at `spec`, giving up after `timeout`.
pub async fn probe(spec: &TransportSpec, timeout: Duration) -> Result<ProbeResult> {
    let host = tokio::time::timeout(timeout, Host::open(spec, HostConfig::default()))
        .await
        .map_err(|_| Error::Timeout("the controller to answer a probe"))??;
    let c = host.capabilities();
    Ok(ProbeResult {
        address: (c.public_address != [0; 6])
            .then(|| crate::Address::public(c.public_address).to_string()),
        manufacturer: c.manufacturer,
        manufacturer_name: c.manufacturer_name(),
        hci_version: c.hci_version,
        version_name: c.version_name(),
        lmp_subversion: c.lmp_subversion,
        le_features: c.le_feature_names(),
        adv_sets: c.adv_sets,
    })
}
