//! Ruuvi sensors (manufacturer data 0x0499), decoded by the
//! [`ruuvi_sensor_protocol`] crate, used as published; this module only
//! maps its values to readings.

use super::Reading;
use ruuvi_sensor_protocol::{
    Acceleration, BatteryPotential, CarbonDioxide, Humidity, Luminosity, MacAddress,
    MeasurementSequenceNumber, MovementCounter, NitrogenOxides, ParticulateMatter, Pressure,
    SensorValues, Temperature, TransmitterPower, VolatileOrganicCompounds,
};

#[cfg(feature = "serde")]
use serde::Serialize;

/// Ruuvi Innovations' company identifier.
pub const COMPANY_ID: u16 = 0x0499;

/// A Ruuvi frame's values, in SI-ish units.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Ruuvi {
    /// Temperature, °C.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub temperature: Option<f64>,
    /// Relative humidity, %.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub humidity: Option<f64>,
    /// Pressure, hPa.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub pressure: Option<f64>,
    /// Acceleration, mg, x y z.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub acceleration: Option<[i16; 3]>,
    /// Battery, V.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub battery: Option<f64>,
    /// TX power, dBm.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub tx_power: Option<i8>,
    /// Movement counter.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub movement_counter: Option<u32>,
    /// Measurement sequence number.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub sequence: Option<u32>,
    /// PM2.5, µg/m³.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub pm2_5: Option<f64>,
    /// CO2, ppm.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub co2: Option<u16>,
    /// VOC index.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub voc_index: Option<u16>,
    /// NOx index.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub nox_index: Option<u16>,
    /// Illuminance, lux.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub illuminance: Option<f64>,
    /// The MAC address the tag reports, as printed.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mac: Option<String>,
}

/// Decodes Ruuvi manufacturer data (after the company identifier).
pub fn decode(company_id: u16, data: &[u8]) -> Option<Ruuvi> {
    if company_id != COMPANY_ID {
        return None;
    }
    let v = SensorValues::from_manufacturer_specific_data(company_id, data).ok()?;
    Some(Ruuvi {
        temperature: v
            .temperature_as_millicelsius()
            .map(|t| f64::from(t) / 1000.0),
        humidity: v.humidity_as_ppm().map(|h| f64::from(h) / 10_000.0),
        pressure: v.pressure_as_pascals().map(|p| f64::from(p) / 100.0),
        acceleration: v.acceleration_vector_as_milli_g().map(|a| [a.0, a.1, a.2]),
        battery: v
            .battery_potential_as_millivolts()
            .map(|b| f64::from(b) / 1000.0),
        tx_power: v.tx_power_as_dbm(),
        movement_counter: v.movement_counter(),
        sequence: v.measurement_sequence_number(),
        pm2_5: v
            .pm2_5_as_nanograms_per_cubic_meter()
            .map(|p| f64::from(p) / 1000.0),
        co2: v.carbon_dioxide_as_ppm(),
        voc_index: v.voc_index(),
        nox_index: v.nox_index(),
        illuminance: v.luminosity_as_millilux().map(|l| f64::from(l) / 1000.0),
        mac: v.mac_address().map(|m| {
            m.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        }),
    })
}

impl Ruuvi {
    pub(crate) fn readings(&self) -> Vec<Reading> {
        let mut v = Vec::new();
        let mut push = |k: &str, x: Option<f64>, u: &'static str| {
            if let Some(x) = x {
                v.push(Reading::new(k, x, u));
            }
        };
        push("temperature", self.temperature, "°C");
        push("humidity", self.humidity, "%");
        push("pressure", self.pressure, "hPa");
        push("voltage", self.battery, "V");
        push("pm2_5", self.pm2_5, "µg/m³");
        push("co2", self.co2.map(f64::from), "ppm");
        push("voc_index", self.voc_index.map(f64::from), "");
        push("nox_index", self.nox_index.map(f64::from), "");
        push("illuminance", self.illuminance, "lx");
        push("movement_counter", self.movement_counter.map(f64::from), "");
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_format_5() {
        // Ruuvi's own test vector for data format 5 (RAWv2).
        let data = hex::decode("0512FC5394C37C0004FFFC040CAC364200CDCBB8334C884F").unwrap();
        let r = decode(COMPANY_ID, &data).unwrap();
        assert_eq!(r.temperature, Some(24.3));
        assert_eq!(r.pressure, Some(1000.44));
        assert_eq!(r.mac.as_deref(), Some("CB:B8:33:4C:88:4F"));
        assert!(decode(COMPANY_ID, &[0x05]).is_none());
    }
}
