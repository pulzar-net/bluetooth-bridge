//! The bridge's configuration file (TOML).

use std::path::{Path, PathBuf};

use bluetooth_host::gatt::server::ServiceDef;
use bluetooth_host::{AdvertisingParams, IoCapability, ScanConfig};
use serde::Deserialize;

/// The whole file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The controller.
    pub adapter: AdapterConfig,
    /// The broker.
    #[serde(default)]
    pub mqtt: MqttConfig,
    /// Scanning.
    #[serde(default)]
    pub scan: ScanSection,
    /// Home Assistant discovery.
    #[serde(default)]
    pub homeassistant: HomeAssistantConfig,
    /// Where bonds and the local identity live.
    #[serde(default)]
    pub data: DataConfig,
    /// BTHome bind keys, for encrypted BTHome devices.
    #[serde(default)]
    pub bthome_keys: Vec<KeyEntry>,
    /// KKM beacon passwords, for encrypted KKM sensor frames.
    #[serde(default)]
    pub kkm_passwords: Vec<PasswordEntry>,
    /// IRKs of devices known without pairing, so their private addresses resolve.
    #[serde(default)]
    pub irks: Vec<IrkEntry>,
    /// GATT services the bridge serves.
    #[serde(default)]
    pub gatt_services: Vec<ServiceDef>,
    /// Advertising sets started with the bridge.
    #[serde(default)]
    pub advertising: Vec<AdvertisingEntry>,
}

/// The controller.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    /// `hci0`, `serial:/dev/ttyAMA0:115200`, or `tcp:host:port`.
    pub transport: String,
    /// The GAP device name.
    #[serde(default = "default_name")]
    pub name: String,
    /// The GAP appearance.
    #[serde(default)]
    pub appearance: u16,
    /// Input and output capabilities for pairing.
    #[serde(default = "default_io")]
    pub io_capability: IoCapability,
    /// A fixed passkey to show and type when pairing needs one (six digits).
    #[serde(default)]
    pub passkey: Option<u32>,
    /// Bond when pairing.
    #[serde(default = "yes")]
    pub bonding: bool,
    /// Require MITM protection.
    #[serde(default)]
    pub mitm: bool,
    /// Refuse legacy pairing.
    #[serde(default)]
    pub secure_connections_only: bool,
    /// Use a static random address even when the controller has a public one.
    #[serde(default)]
    pub random_address: bool,
}

fn default_name() -> String {
    "bluetooth-bridge".into()
}

fn default_io() -> IoCapability {
    IoCapability::NoInputNoOutput
}

fn yes() -> bool {
    true
}

/// The broker.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MqttConfig {
    /// Host name.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name.
    pub username: Option<String>,
    /// A file holding the password (so it is not in this file).
    pub password_file: Option<PathBuf>,
    /// Client id.
    pub client_id: String,
    /// Every topic starts with this.
    pub base_topic: String,
    /// Keep-alive, seconds.
    pub keepalive: u64,
}

impl Default for MqttConfig {
    fn default() -> Self {
        MqttConfig {
            host: "localhost".into(),
            port: 1883,
            username: None,
            password_file: None,
            client_id: "bluetooth-bridge".into(),
            base_topic: "bluetooth".into(),
            keepalive: 30,
        }
    }
}

/// Scanning. (Unknown keys cannot be refused here: serde does not allow
/// that with a flattened section.)
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanSection {
    /// Scan from start.
    pub enabled: bool,
    /// How.
    #[serde(flatten)]
    pub config: ScanConfig,
    /// Publish only devices whose address starts with one of these
    /// (`BC:57:29`, say); empty publishes everything.
    pub allow: Vec<String>,
    /// Ignore weaker signals, dBm.
    pub min_rssi: i8,
    /// Publish every report on `<base>/scan/<address>`.
    pub publish_reports: bool,
}

impl Default for ScanSection {
    fn default() -> Self {
        ScanSection {
            enabled: true,
            config: ScanConfig::default(),
            allow: Vec::new(),
            min_rssi: -127,
            publish_reports: true,
        }
    }
}

/// Home Assistant discovery.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HomeAssistantConfig {
    /// Publish discovery for devices with decoded readings.
    pub enabled: bool,
    /// The discovery prefix.
    pub discovery_prefix: String,
    /// Home Assistant's birth topic; discovery is sent again when it comes online.
    pub status_topic: String,
}

impl Default for HomeAssistantConfig {
    fn default() -> Self {
        HomeAssistantConfig {
            enabled: true,
            discovery_prefix: "homeassistant".into(),
            status_topic: "homeassistant/status".into(),
        }
    }
}

/// Storage.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DataConfig {
    /// The data directory.
    pub dir: PathBuf,
}

impl Default for DataConfig {
    fn default() -> Self {
        DataConfig {
            dir: PathBuf::from("/var/lib/bluetooth-bridge"),
        }
    }
}

/// A device's key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// The device's address.
    pub address: String,
    /// The 16-byte key, hex.
    pub key: String,
}

/// A device's password.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordEntry {
    /// The device's address.
    pub address: String,
    /// The password.
    pub password: String,
}

/// A known IRK.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrkEntry {
    /// The identity address the device's private addresses stand for.
    pub address: String,
    /// The IRK, hex, most significant byte first.
    pub irk: String,
    /// A label.
    #[serde(default)]
    pub label: Option<String>,
}

/// An advertising set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertisingEntry {
    /// How.
    #[serde(default)]
    pub params: AdvertisingParams,
    /// Advertising data, hex (AD structures).
    #[serde(default)]
    pub data: String,
    /// Scan response, hex.
    #[serde(default)]
    pub scan_response: String,
}

/// A configuration problem.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Reading the file.
    #[error("{0}: {1}")]
    Read(PathBuf, std::io::Error),
    /// Parsing it.
    #[error("{0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    /// A value that parses but makes no sense.
    #[error("{0}")]
    Invalid(String),
}

impl Config {
    /// Reads and checks a file.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
        let c: Config =
            toml::from_str(&text).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))?;
        c.check()?;
        Ok(c)
    }

    /// Parses from a string (tests).
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let c: Config =
            toml::from_str(text).map_err(|e| ConfigError::Parse(PathBuf::from("<config>"), e))?;
        c.check()?;
        Ok(c)
    }

    fn check(&self) -> Result<(), ConfigError> {
        let bad = |m: String| Err(ConfigError::Invalid(m));
        if self
            .adapter
            .transport
            .parse::<bluetooth_host::TransportSpec>()
            .is_err()
        {
            return bad(format!(
                "adapter.transport {:?} is not hciN, serial:PATH:BAUD or tcp:HOST:PORT",
                self.adapter.transport
            ));
        }
        if self.adapter.passkey.is_some_and(|p| p > 999_999) {
            return bad("adapter.passkey has six digits at most".into());
        }
        for k in &self.bthome_keys {
            if k.address.parse::<bluetooth_host::Address>().is_err()
                || hex::decode(&k.key).map(|v| v.len()) != Ok(16)
            {
                return bad(format!(
                    "bthome_keys entry for {:?} needs an address and a 32-digit hex key",
                    k.address
                ));
            }
        }
        for k in &self.irks {
            if k.address.parse::<bluetooth_host::Address>().is_err()
                || u128::from_str_radix(&k.irk, 16).is_err()
            {
                return bad(format!(
                    "irks entry for {:?} needs an address and a 32-digit hex IRK",
                    k.address
                ));
            }
        }
        for p in &self.kkm_passwords {
            if p.address.parse::<bluetooth_host::Address>().is_err() || p.password.len() > 16 {
                return bad(format!(
                    "kkm_passwords entry {:?}: an address and a password of 16 characters at most",
                    p.address
                ));
            }
        }
        for a in &self.advertising {
            if hex::decode(&a.data).is_err() || hex::decode(&a.scan_response).is_err() {
                return bad("advertising data and scan_response are hex".into());
            }
        }
        if self.mqtt.base_topic.is_empty() || self.mqtt.base_topic.contains(['+', '#']) {
            return bad("mqtt.base_topic must be a plain topic".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses() {
        let c = Config::parse(include_str!("../../../config.example.toml")).unwrap();
        assert_eq!(c.adapter.transport, "hci0");
        assert_eq!(c.mqtt.base_topic, "bluetooth");
        assert!(c.scan.enabled);
    }

    #[test]
    fn minimal_and_errors() {
        let c = Config::parse("[adapter]\ntransport = \"tcp:127.0.0.1:9000\"\n").unwrap();
        assert!(c.homeassistant.enabled);
        assert!(Config::parse("[adapter]\ntransport = \"usb:1\"\n").is_err());
        assert!(Config::parse("[adapter]\ntransport = \"hci0\"\npasskey = 1234567\n").is_err());
        assert!(Config::parse("[adapter]\ntransport = \"hci0\"\nbogus = 1\n").is_err());
    }
}
