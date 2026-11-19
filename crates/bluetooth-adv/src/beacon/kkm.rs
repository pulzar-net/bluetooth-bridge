//! KKM KBeacon frames, as KKM's own MIT-licensed SDK reads them
//! (<https://github.com/kkmhogen/android_kbeaconlib2>, `KBAdvPackage`).
//!
//! | Frame | Carried in | First byte |
//! |---|---|---|
//! | Sensor v1: a 16-bit mask, then the readings it names | Eddystone service data (0xFEAA) | 0x21 |
//! | Sensor v1, encrypted | manufacturer data 0x0A53 | 0x06 |
//! | Sensor v2: a model byte, battery, then length-type-value records | manufacturer data 0x0A53 | 0x24 |
//! | Sensor v2, encrypted | manufacturer data 0x0A53 | 0x07 |
//! | System: model, battery %, MAC, firmware | Eddystone service data | 0x22 |
//!
//! Encrypted frames carry 16 bytes of AES-128-ECB ciphertext and a 4-byte
//! UTC second count; the key is MD5(password padded to 16 bytes || MAC as
//! printed || UTC seconds).

use super::{Context, Reading};
use crate::reader::Reader;
use crate::AddressBytes;

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};

#[cfg(feature = "serde")]
use serde::Serialize;

/// KKM's company identifier.
pub const COMPANY_ID: u16 = 0x0a53;

/// A KKM frame.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Kkm {
    /// `sensor` or `system`.
    pub frame: &'static str,
    /// Encrypted on the air.
    pub encrypted: bool,
    /// Encrypted, and no password (or no address) to decrypt it with. When
    /// the password is wrong the readings are garbage: KKM's format has no
    /// integrity check.
    pub undecryptable: bool,
    /// Device model (v2 sensor and system frames).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub model: Option<u8>,
    /// Battery voltage, mV (sensor frames).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub battery_mv: Option<u16>,
    /// Battery, percent (system frames).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub battery_percent: Option<u8>,
    /// Temperature, °C.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub temperature: Option<f64>,
    /// Relative humidity, %.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub humidity: Option<f64>,
    /// Three-axis reading (accelerometer in mg, or magnetometer on the S7S).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub axis: Option<[i16; 3]>,
    /// Alarm byte. Its bits are model specific; on the S7S parking sensor
    /// bits 0-1 are park status and bits 4-5 radar status.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub alarm: Option<u8>,
    /// PIR indication.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub pir: Option<u8>,
    /// Illuminance, lux.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub lux: Option<u16>,
    /// VOC index, and seconds since it was measured.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub voc: Option<(u16, u32)>,
    /// NOx index.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub nox: Option<u16>,
    /// CO2, ppm, and seconds since it was measured.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub co2: Option<(u16, u32)>,
    /// New history records: record type and count.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub new_records: Option<(u8, u16)>,
    /// UTC seconds sent with an encrypted frame.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub utc: Option<u32>,
    /// The beacon's own MAC address, as printed (system frames).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mac: Option<String>,
    /// Firmware version (system frames).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub firmware: Option<String>,
}

const MASK_VOLTAGE: u16 = 0x0001;
const MASK_TEMP: u16 = 0x0002;
const MASK_HUMIDITY: u16 = 0x0004;
const MASK_AXIS: u16 = 0x0008;
const MASK_ALARM: u16 = 0x0010;
const MASK_PIR: u16 = 0x0020;
const MASK_LUX: u16 = 0x0040;
const MASK_VOC: u16 = 0x0080;
const MASK_CO2: u16 = 0x0200;
const MASK_RECORDS: u16 = 0x0400;

/// Decodes a frame in Eddystone service data (types 0x21 and 0x22).
pub fn decode_service_data(data: &[u8], _ctx: &Context) -> Option<Kkm> {
    let mut r = Reader::new(data);
    match r.u8()? {
        0x21 => {
            let mask = r.u16_be()?;
            Some(sensor_v1(mask, r.rest()))
        }
        0x22 => {
            let _tag = r.u8()?;
            let model = r.u8()?;
            let battery = r.u8()?;
            let mac: [u8; 6] = r.array()?;
            let fw: [u8; 2] = r.array()?;
            Some(Kkm {
                frame: "system",
                model: Some(model),
                battery_percent: Some(battery.min(100)),
                mac: Some(
                    mac.iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                ),
                firmware: Some(format!("{}.{}", fw[0], fw[1])),
                ..Kkm::default()
            })
        }
        _ => None,
    }
}

/// Decodes a frame in KKM's manufacturer data (types 0x06, 0x07 and 0x24).
/// Encrypted frames are decrypted when `ctx` has the advertiser's address
/// and a password for it.
pub fn decode_manufacturer(company_id: u16, data: &[u8], ctx: &Context) -> Option<Kkm> {
    if company_id != COMPANY_ID || data.len() < 3 {
        return None;
    }
    match data[0] {
        kind @ (0x06 | 0x07) => {
            // type, mask (2) or model (1), ciphertext (16), UTC (4)
            let header = if kind == 0x06 { 3 } else { 2 };
            let utc: [u8; 4] = data.get(header + 16..header + 20)?.try_into().ok()?;
            let password = ctx
                .address
                .and_then(|a| ctx.kkm_passwords.get(&a).map(|p| (a, p)));
            match password {
                Some((addr, p)) => decode_with_password(data, &addr, p),
                None => Some(Kkm {
                    frame: "sensor",
                    encrypted: true,
                    undecryptable: true,
                    model: (kind == 0x07).then_some(data[1]),
                    utc: Some(u32::from_be_bytes(utc)),
                    ..Kkm::default()
                }),
            }
        }
        0x24 => {
            let mut k = sensor_v2(&data[2..]);
            k.model = Some(data[1]);
            Some(k)
        }
        _ => None,
    }
}

fn decode_with_password(data: &[u8], addr: &AddressBytes, password: &str) -> Option<Kkm> {
    let mut r = Reader::new(data);
    let kind = r.u8()?;
    let (mask, model) = match kind {
        0x06 => (Some(r.u16_be()?), None),
        0x07 => (None, Some(r.u8()?)),
        _ => return None,
    };
    let ct: [u8; 16] = r.array()?;
    let utc_bytes: [u8; 4] = r.array()?;
    let mut key_material = [0u8; 26];
    let pwd = password.as_bytes();
    let n = pwd.len().min(16);
    key_material[..n].copy_from_slice(&pwd[..n]);
    for (i, b) in addr.iter().rev().enumerate() {
        key_material[16 + i] = *b;
    }
    key_material[22..].copy_from_slice(&utc_bytes);
    let key: [u8; 16] = Md5::digest(key_material).into();
    let mut block = aes::Block::from(ct);
    Aes128::new(&key.into()).decrypt_block(&mut block);
    let plain: [u8; 16] = block.into();
    let mut k = match mask {
        Some(mask) => sensor_v1(mask, &plain),
        None => sensor_v2(&plain),
    };
    k.encrypted = true;
    k.model = model;
    k.utc = Some(u32::from_be_bytes(utc_bytes));
    Some(k)
}

fn sensor_v1(mask: u16, data: &[u8]) -> Kkm {
    let mut k = Kkm {
        frame: "sensor",
        ..Kkm::default()
    };
    let mut r = Reader::new(data);
    // Fields appear in mask order; stop at the first one that does not fit,
    // keeping those before it.
    let _ = (|| -> Option<()> {
        if mask & MASK_VOLTAGE != 0 {
            k.battery_mv = Some(r.u16_be()?);
        }
        if mask & MASK_TEMP != 0 {
            k.temperature = Some(fixed_8_8(r.i16_be()?));
        }
        if mask & MASK_HUMIDITY != 0 {
            let h = r.array::<2>()?;
            if (h[0] as i8) >= 0 {
                k.humidity = Some(fixed_8_8(i16::from_be_bytes(h)));
            } else if (h[0] as i8) < -2 {
                // A wide-range thermometer: the high byte extends the temperature.
                if let Some(t) = k.temperature {
                    k.temperature = Some(f64::from(-20 - i32::from(h[0] as i8)) * 100.0 + t);
                }
            }
        }
        if mask & MASK_AXIS != 0 {
            k.axis = Some([r.i16_be()?, r.i16_be()?, r.i16_be()?]);
        }
        if mask & MASK_ALARM != 0 {
            k.alarm = Some(r.u8()?);
        }
        if mask & MASK_PIR != 0 {
            k.pir = Some(r.u8()?);
        }
        if mask & MASK_LUX != 0 {
            k.lux = Some(r.u16_be()?);
        }
        if mask & MASK_VOC != 0 {
            let elapsed = u32::from(r.u8()?) * 10;
            k.voc = Some((r.u16_be()?, elapsed));
            k.nox = Some(r.u16_be()?);
        }
        if mask & MASK_CO2 != 0 {
            let elapsed = u32::from(r.u8()?) * 10;
            k.co2 = Some((r.u16_be()?, elapsed));
        }
        if mask & MASK_RECORDS != 0 {
            k.new_records = Some((r.u8()?, r.u16_be()?));
        }
        Some(())
    })();
    k
}

fn sensor_v2(data: &[u8]) -> Kkm {
    let mut k = Kkm {
        frame: "sensor",
        ..Kkm::default()
    };
    let mut r = Reader::new(data);
    let Some(b) = r.u16_be() else { return k };
    k.battery_mv = Some(b);
    let Some(_t0) = r.u8() else { return k };
    while r.remaining() >= 2 {
        let (Some(len), Some(kind)) = (r.u8(), r.u8()) else {
            break;
        };
        let Some(v) = r.take(usize::from(len.saturating_sub(1))) else {
            break;
        };
        let mut f = Reader::new(v);
        match kind {
            0x02 => k.temperature = f.i16_be().map(|t| f64::from(t) / 10.0),
            0x03 => {
                k.temperature = f.i16_be().map(|t| f64::from(t) / 10.0);
                k.humidity = f.i8().map(f64::from);
            }
            0x04 => {
                if let (Some(x), Some(y), Some(z)) = (f.i16_be(), f.i16_be(), f.i16_be()) {
                    k.axis = Some([x, y, z]);
                }
            }
            0x05 => k.alarm = f.u8(),
            0x06 => k.pir = f.u8(),
            0x07 => k.lux = f.u16_be(),
            0x08 => {
                if let (Some(e), Some(voc), Some(nox)) = (f.u8(), f.u16_be(), f.u16_be()) {
                    k.voc = Some((voc, u32::from(e) * 10));
                    k.nox = Some(nox);
                }
            }
            0x09 => {
                if let (Some(e), Some(co2)) = (f.u8(), f.u16_be()) {
                    k.co2 = Some((co2, u32::from(e) * 10));
                }
            }
            0x0a => {
                if let (Some(t), Some(n)) = (f.u8(), f.u16_be()) {
                    k.new_records = Some((t, n));
                }
            }
            _ => {}
        }
    }
    k
}

fn fixed_8_8(v: i16) -> f64 {
    (f64::from(v) / 256.0 * 100.0).round() / 100.0
}

impl Kkm {
    pub(crate) fn readings(&self) -> Vec<Reading> {
        let mut v = Vec::new();
        if let Some(b) = self.battery_mv {
            v.push(Reading::new("voltage", f64::from(b) / 1000.0, "V"));
        }
        if let Some(b) = self.battery_percent {
            v.push(Reading::new("battery", f64::from(b), "%"));
        }
        if let Some(t) = self.temperature {
            v.push(Reading::new("temperature", t, "°C"));
        }
        if let Some(h) = self.humidity {
            v.push(Reading::new("humidity", h, "%"));
        }
        if let Some([x, y, z]) = self.axis {
            v.push(Reading::new("x", f64::from(x), ""));
            v.push(Reading::new("y", f64::from(y), ""));
            v.push(Reading::new("z", f64::from(z), ""));
        }
        if let Some(a) = self.alarm {
            v.push(Reading::new("alarm", f64::from(a), ""));
        }
        if let Some(p) = self.pir {
            v.push(Reading::new("pir", f64::from(p), ""));
        }
        if let Some(l) = self.lux {
            v.push(Reading::new("illuminance", f64::from(l), "lx"));
        }
        if let Some((voc, _)) = self.voc {
            v.push(Reading::new("voc_index", f64::from(voc), ""));
        }
        if let Some(n) = self.nox {
            v.push(Reading::new("nox_index", f64::from(n), ""));
        }
        if let Some((c, _)) = self.co2 {
            v.push(Reading::new("co2", f64::from(c), "ppm"));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s7s_sensor_frame() {
        // Mask: voltage, temperature, axis, alarm. 3000 mV, 25.5 °C, (-1, 2, 3), occupied.
        let data = hex::decode("21 001b 0bb8 1980 ffff00020003 01".replace(' ', "")).unwrap();
        let k = decode_service_data(&data, &Context::default()).unwrap();
        assert_eq!(k.battery_mv, Some(3000));
        assert_eq!(k.temperature, Some(25.5));
        assert_eq!(k.axis, Some([-1, 2, 3]));
        assert_eq!(k.alarm, Some(1));
        // Truncated: what fits is kept.
        let k = decode_service_data(&data[..7], &Context::default()).unwrap();
        assert_eq!(k.temperature, Some(25.5));
        assert_eq!(k.axis, None);
    }

    #[test]
    fn system_frame() {
        let data = hex::decode("22 00 07 64 bc5729000001 0638".replace(' ', "")).unwrap();
        let k = decode_service_data(&data, &Context::default()).unwrap();
        assert_eq!(k.frame, "system");
        assert_eq!(k.mac.as_deref(), Some("BC:57:29:00:00:01"));
        assert_eq!(k.firmware.as_deref(), Some("6.56"));
        assert_eq!(k.battery_percent, Some(100));
    }

    #[test]
    fn v2_records() {
        // model 5, 3100 mV, t0, temp+humidity 21.5 °C 40 %, lux 300.
        let data = hex::decode("24 05 0c1c 00 04 03 00d7 28 03 07 012c".replace(' ', "")).unwrap();
        let k = decode_manufacturer(COMPANY_ID, &data, &Context::default()).unwrap();
        assert_eq!(k.model, Some(5));
        assert_eq!(k.battery_mv, Some(3100));
        assert_eq!(k.temperature, Some(21.5));
        assert_eq!(k.humidity, Some(40.0));
        assert_eq!(k.lux, Some(300));
    }

    #[test]
    fn encrypted_v1_decrypts_with_password() {
        use aes::cipher::BlockCipherEncrypt;
        let addr: AddressBytes = [0x01, 0x00, 0x00, 0x29, 0x57, 0xbc];
        let utc = 1_700_000_000u32.to_be_bytes();
        let mut km = [0u8; 26];
        km[..4].copy_from_slice(b"1234");
        km[16..22].copy_from_slice(&[0xbc, 0x57, 0x29, 0x00, 0x00, 0x01]);
        km[22..].copy_from_slice(&utc);
        let key: [u8; 16] = Md5::digest(km).into();
        let mut plain = [0u8; 16];
        plain[..4].copy_from_slice(&[0x0b, 0xb8, 0x19, 0x80]);
        let mut block = aes::Block::from(plain);
        Aes128::new(&key.into()).encrypt_block(&mut block);
        let mut data = vec![0x06, 0x00, 0x03];
        data.extend_from_slice(&<[u8; 16]>::from(block));
        data.extend_from_slice(&utc);

        let mut ctx = Context::for_address(addr);
        let locked = decode_manufacturer(COMPANY_ID, &data, &ctx).unwrap();
        assert!(locked.encrypted && locked.undecryptable);
        ctx.kkm_passwords.insert(addr, "1234".into());
        let k = decode_manufacturer(COMPANY_ID, &data, &ctx).unwrap();
        assert!(!k.undecryptable);
        assert_eq!(k.battery_mv, Some(3000));
        assert_eq!(k.temperature, Some(25.5));
    }
}
