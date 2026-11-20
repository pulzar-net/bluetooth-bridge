---
title: "Getting started"
description: "This page runs bluetooth-bridge end to end without Bluetooth hardware."
---

This page runs bluetooth-bridge end to end without Bluetooth hardware. A
virtual controller from [Bumble](https://github.com/google/bumble) takes
the place of a real one, and a second Bumble device on the same simulated
radio link advertises like a BTHome temperature sensor. The bridge talks to
the virtual controller over H4 on TCP, exactly as it would to a real one.

You need:

- Rust 1.89 or newer ([rustup.rs](https://rustup.rs)), or a release binary;
- Python 3.10 or newer, for Bumble;
- an MQTT broker and its command-line clients, for example Mosquitto
  (`apt install mosquitto mosquitto-clients`, or `brew install mosquitto`);
- optionally, Home Assistant with its MQTT integration on the same broker.

## 1. Start a virtual controller and a sensor

```sh
git clone --recurse-submodules https://github.com/pulzar-net/bluetooth-bridge
cd bluetooth-bridge
python3 -m venv .venv
.venv/bin/pip install -r tests/bumble/requirements.txt
.venv/bin/python tests/bumble/peer.py scan_legacy 9000
```

This is the scripted peer the end-to-end tests use. The `scan_legacy`
scenario serves a virtual controller on TCP port 9000 and makes the peer,
`bumble-peer` at `F1:22:33:44:55:66`, advertise BTHome readings
(25.06 °C, 50.55 %). Leave it running.

## 2. Configure and run the bridge

In a second terminal, write `quickstart.toml`:

```toml
[adapter]
transport = "tcp:127.0.0.1:9000"

[mqtt]
host = "localhost"

[data]
dir = "./data"
```

and run it:

```sh
cargo run -p bluetooth-bridge -- --config quickstart.toml
```

```text
INFO MQTT connected
INFO controller D0:11:22:33:44:55 (unknown manufacturer), Bluetooth® Core Specification 5.0, LE features: le_encryption, ...
```

## 3. Watch MQTT

```sh
mosquitto_sub -h localhost -t 'bluetooth/#' -v
```

Within a second or two:

```text
bluetooth/scan/F12233445566 {"address":"F1:22:33:44:55:66/random","advertisement":{...,"local_name":{"complete":true,"name":"bumble-peer"},...},"beacons":[{"format":"bt_home","measurements":[{"name":"temperature","value":25.06,"unit":"°C",...},...]}],...}
bluetooth/device/F12233445566 {"humidity":50.55,"last_seen":1795138399393,"rssi":-50,"temperature":25.06}
```

`scan/...` is everything in the advertisement; `device/...` is the decoded
readings. Home Assistant, if connected, now has a device with temperature,
humidity and signal strength sensors.

## 4. Send a request

Requests go to `bluetooth/bridge/request/<op>` and are answered on
`bluetooth/bridge/response/<op>`:

```sh
mosquitto_pub -h localhost -t bluetooth/bridge/request/connections -m '{"transaction": "1"}'
# bluetooth/bridge/response/connections {"data":[],"status":"ok","transaction":"1"}
```

The other scenarios in `tests/bumble/peer.py` (`peripheral`, `central`,
`periodic`, `rpa` and more) exercise connections, GATT, pairing and
privacy the same way.

## Next steps

- [Install](/bluetooth-bridge/installation.html) a release binary as a service.
- [Pick a controller](/bluetooth-bridge/hardware.html) and set `adapter.transport` to it.
  `bluetooth-bridge probe hci0` shows what it can do.
- Read [Sensors and beacons](/bluetooth-bridge/sensors.html) for encrypted sensors, and the
  [MQTT API](/bluetooth-bridge/mqtt.html) for every request.
