---
title: "Sensors and beacons"
description: "Most Bluetooth LE sensors never need a connection: they put their readings in advertisements, and anything in range can read them."
---

Most Bluetooth LE sensors never need a connection: they put their readings
in advertisements, and anything in range can read them. bluetooth-bridge
decodes the common formats, publishes the readings on
`bluetooth/device/<ADDRESS>`, and creates a Home Assistant device for each
sensor. Every advertisement, decoded or not, is also published raw and
parsed on `bluetooth/scan/<ADDRESS>`.

## Formats

| Format | Devices | What is decoded |
|---|---|---|
| BTHome v2 | Shelly BLU devices, sensors running BTHome firmware (for example the pvvx/ATC firmware for Xiaomi thermometers), DIY sensors | every BTHome object (temperature, humidity, pressure, illuminance, battery, motion, door, buttons, energy, ...); encrypted frames with the device's bind key |
| Ruuvi | RuuviTag | data formats the `ruuvi-sensor-protocol` crate reads (format 5, RAWv2, among them): temperature, humidity, pressure, acceleration, battery voltage, movement counter |
| KKM KBeacon | KKM sensors and beacons | sensor frames (v1 and v2), encrypted frames with the beacon's password, system frames |
| iBeacon | Apple iBeacon format | UUID, major, minor, measured power |
| AltBeacon | | beacon id, reference RSSI |
| Eddystone | | UID, URL, TLM (battery, temperature, counters), encrypted TLM, EID |

Readings take their names and units from the format (BTHome's object names,
for instance), so the same quantity has the same key everywhere:
`temperature` in °C, `humidity` in %, `battery` in %, `voltage` in V.

## Encrypted BTHome sensors

An encrypted BTHome sensor needs its 16-byte bind key, which the device's
app or firmware shows:

```toml
[[bthome_keys]]
address = "A4:C1:38:00:00:01"
key = "231d39c1d7cc1ab1aee224cd096db932"
```

Without the key, the sensor's frames are reported with `"encrypted": true`
and `"undecryptable": true` and no readings.

## Encrypted KKM frames

```toml
[[kkm_passwords]]
address = "BC:57:29:00:00:01"
password = "0000000000000000"
```

## Devices with private addresses

Phones, watches and many tags use resolvable private addresses that change
every few minutes, so without help they look like a new device each time.
Two ways to keep them one device:

- **Pair with them.** A bond includes the device's IRK, and the bridge
  resolves its addresses from then on (see
  [Connections, GATT and pairing](/bluetooth-bridge/connections.html)).
- **Enter the IRK** when you know it without pairing (some tags print it,
  or you exported it from another system):

```toml
[[irks]]
address = "C0:11:22:33:44:55/random"   # the identity its addresses resolve to
irk = "ec0234a357c8ad05341010a60a397d9b"
label = "tag 1"
```

Resolved advertisements carry an `identity` field, and their topics use the
identity address.

## Range and the coded PHY

With `scan.coded = true` (the default) and a Bluetooth 5 controller that
supports it, the bridge also scans the coded PHY (Bluetooth "long range"),
which some sensors use to reach further. Older controllers scan the 1M PHY
only; `bluetooth/bridge/info` lists the features yours has.

> Needs real hardware: range and reception depend on the controller and its
> antenna, which the virtual controller in CI does not model.

## Adding a format

Formats live in [bluetooth-adv](/bluetooth-bridge/library/bluetooth-adv.html), with no I/O, so a
new one is a parser and its tests against captured advertisements. See
[CONTRIBUTING.md](https://github.com/pulzar-net/bluetooth-bridge/blob/main/CONTRIBUTING.md).
