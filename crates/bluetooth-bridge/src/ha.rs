//! Home Assistant MQTT discovery for devices whose advertisements decode to
//! readings (BTHome, KKM, Ruuvi, Eddystone TLM).

use serde_json::{json, Value};

/// BTHome's binary states, which become binary sensors.
const BINARY: &[(&str, &str)] = &[
    ("generic_boolean", ""),
    ("power_on", "power"),
    ("opening", "opening"),
    ("battery_low", "battery"),
    ("battery_charging", "battery_charging"),
    ("carbon_monoxide", "carbon_monoxide"),
    ("cold", "cold"),
    ("connectivity", "connectivity"),
    ("door", "door"),
    ("garage_door", "garage_door"),
    ("gas_detected", "gas"),
    ("heat", "heat"),
    ("light", "light"),
    ("lock", "lock"),
    ("moisture_detected", "moisture"),
    ("motion", "motion"),
    ("moving", "moving"),
    ("occupancy", "occupancy"),
    ("plug", "plug"),
    ("presence", "presence"),
    ("problem", "problem"),
    ("running", "running"),
    ("safety", "safety"),
    ("smoke", "smoke"),
    ("sound", "sound"),
    ("tamper", "tamper"),
    ("vibration", "vibration"),
    ("window", "window"),
];

/// Home Assistant's device class for a reading, by key and unit.
fn device_class(key: &str, unit: &str) -> Option<&'static str> {
    let base = key.trim_end_matches(|c: char| c.is_ascii_digit() || c == '_');
    Some(match base {
        "temperature" | "dewpoint" => "temperature",
        "humidity" => "humidity",
        "moisture" => "moisture",
        "battery" if unit == "%" => "battery",
        "voltage" => "voltage",
        "pressure" => "atmospheric_pressure",
        "illuminance" => "illuminance",
        "co2" => "carbon_dioxide",
        "pm2_5" => "pm25",
        "pm10" => "pm10",
        "tvoc" => "volatile_organic_compounds",
        "energy" => "energy",
        "power" => "power",
        "current" => "current",
        "mass" => "weight",
        "distance" => "distance",
        "speed" => "speed",
        "volume" | "volume_storage" => "volume",
        "water" => "water",
        "gas" => "gas",
        "duration" => "duration",
        "rssi" => "signal_strength",
        "conductivity" => "conductivity",
        "precipitation" => "precipitation",
        _ => return None,
    })
}

fn is_cumulative(key: &str) -> bool {
    matches!(
        key.trim_end_matches(|c: char| c.is_ascii_digit() || c == '_'),
        "energy" | "gas" | "water" | "volume"
    )
}

/// The discovery topic and payload for one reading of one device.
#[allow(clippy::too_many_arguments)]
pub fn entity(
    prefix: &str,
    base: &str,
    device_id: &str,
    device_name: &str,
    model: &str,
    manufacturer: Option<&str>,
    key: &str,
    unit: &str,
) -> (String, Value) {
    let binary = BINARY.iter().find(|(k, _)| *k == key);
    let component = if binary.is_some() {
        "binary_sensor"
    } else {
        "sensor"
    };
    let object = format!("bluetooth_{}_{key}", device_id.to_lowercase());
    let mut c = json!({
        "name": key.replace('_', " "),
        "unique_id": object,
        "object_id": object,
        "state_topic": format!("{base}/device/{device_id}"),
        "availability_topic": crate::mqtt::state_topic(base),
        "availability_template": "{{ value_json.state }}",
        "device": {
            "identifiers": [format!("bluetooth_{}", device_id.to_lowercase())],
            "connections": [["bluetooth", device_id_to_mac(device_id)]],
            "name": device_name,
            "model": model,
            "via_device": bridge_id(base),
        },
    });
    if let Some(m) = manufacturer {
        c["device"]["manufacturer"] = json!(m);
    }
    match binary {
        Some((_, class)) => {
            c["value_template"] = json!(format!("{{{{ 'ON' if value_json.{key} else 'OFF' }}}}"));
            if !class.is_empty() {
                c["device_class"] = json!(class);
            }
        }
        None => {
            c["value_template"] = json!(format!("{{{{ value_json.{key} }}}}"));
            if !unit.is_empty() {
                c["unit_of_measurement"] = json!(unit);
            }
            if let Some(class) = device_class(key, unit) {
                c["device_class"] = json!(class);
            }
            c["state_class"] = json!(if is_cumulative(key) {
                "total_increasing"
            } else {
                "measurement"
            });
            if key == "rssi" {
                c["entity_category"] = json!("diagnostic");
                c["enabled_by_default"] = json!(false);
            }
        }
    }
    (
        format!(
            "{prefix}/{component}/bluetooth_{}/{key}/config",
            device_id.to_lowercase()
        ),
        c,
    )
}

/// The bridge's own device id in Home Assistant, from its base topic, which
/// every bridge on one broker already has to have to itself: `bluetooth_bridge`
/// for the default `bluetooth` (as before there could be more than one, so an
/// existing installation keeps its device), `bluetooth_bridge_<base>` for any
/// other.
pub fn bridge_id(base: &str) -> String {
    if base == "bluetooth" {
        return "bluetooth_bridge".into();
    }
    let slug: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("bluetooth_bridge_{slug}")
}

/// The bridge itself, as a device the sensors come through.
pub fn bridge_device(prefix: &str, base: &str, version: &str) -> (String, Value) {
    let id = bridge_id(base);
    (
        format!("{prefix}/binary_sensor/{id}/connection_state/config"),
        json!({
            "name": "connection state",
            "unique_id": format!("{id}_connection_state"),
            "state_topic": crate::mqtt::state_topic(base),
            "value_template": "{{ 'ON' if value_json.state == 'online' else 'OFF' }}",
            "device_class": "connectivity",
            "entity_category": "diagnostic",
            "device": {
                "identifiers": [id],
                "name": if base == "bluetooth" { "Bluetooth bridge".to_string() } else { format!("Bluetooth bridge {base}") },
                "model": "bluetooth-bridge",
                "sw_version": version,
            },
        }),
    )
}

/// `BC5729000001` back to `BC:57:29:00:00:01`.
fn device_id_to_mac(id: &str) -> String {
    id.as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_bridges_on_one_broker_are_two_devices() {
        let (t1, c1) = bridge_device("homeassistant", "bluetooth", "0");
        let (t2, c2) = bridge_device("homeassistant", "bluetooth/garage", "0");
        assert_eq!(
            t1, "homeassistant/binary_sensor/bluetooth_bridge/connection_state/config",
            "the default bridge keeps its device"
        );
        assert_eq!(
            t2,
            "homeassistant/binary_sensor/bluetooth_bridge_bluetooth_garage/connection_state/config"
        );
        assert_ne!(c1["unique_id"], c2["unique_id"]);
        assert_ne!(c1["device"]["identifiers"], c2["device"]["identifiers"]);
        let (_, s) = entity(
            "homeassistant",
            "bluetooth/garage",
            "BC5729000001",
            "x",
            "m",
            None,
            "temperature",
            "°C",
        );
        assert_eq!(s["device"]["via_device"], c2["device"]["identifiers"][0]);
    }

    #[test]
    fn sensors_and_binary_sensors() {
        let (t, c) = entity(
            "homeassistant",
            "bluetooth",
            "A4C138000001",
            "Living room",
            "BTHome",
            None,
            "temperature",
            "°C",
        );
        assert_eq!(
            t,
            "homeassistant/sensor/bluetooth_a4c138000001/temperature/config"
        );
        assert_eq!(c["device_class"], "temperature");
        assert_eq!(c["state_topic"], "bluetooth/device/A4C138000001");
        assert_eq!(c["value_template"], "{{ value_json.temperature }}");
        assert_eq!(c["device"]["connections"][0][1], "A4:C1:38:00:00:01");
        let (t, c) = entity(
            "homeassistant",
            "bluetooth",
            "A4C138000001",
            "x",
            "BTHome",
            None,
            "door",
            "",
        );
        assert!(t.starts_with("homeassistant/binary_sensor/"));
        assert_eq!(c["device_class"], "door");
        let (_, c) = entity(
            "homeassistant",
            "bluetooth",
            "A",
            "x",
            "m",
            None,
            "temperature_2",
            "°C",
        );
        assert_eq!(c["device_class"], "temperature");
        let (_, c) = entity(
            "homeassistant",
            "bluetooth",
            "A",
            "x",
            "m",
            None,
            "energy",
            "kWh",
        );
        assert_eq!(c["state_class"], "total_increasing");
    }
}
