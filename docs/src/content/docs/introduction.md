---
title: "bluetooth-bridge"
description: "bluetooth-bridge is a Bluetooth host stack that runs directly on HCI, and a Bluetooth LE to MQTT bridge, written in Rust."
---

bluetooth-bridge is a Bluetooth host stack that runs directly on HCI, and a
Bluetooth LE to MQTT bridge, written in Rust. It drives a Bluetooth
controller with no BlueZ and no D-Bus, decodes beacons and sensors, and
publishes them to MQTT with Home Assistant discovery; connections, GATT,
pairing and advertising are MQTT requests. It is a single static binary
with no runtime, small enough for routers and gateways, and a set of
library crates for anyone building Bluetooth software in Rust.

This site is the user guide and the reference. The
[README](https://github.com/pulzar-net/bluetooth-bridge#readme) is the
two-minute overview; the [API docs](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_host/index.html)
cover every type and function.

## Where to start

| You want to | Read |
|---|---|
| try it without hardware | [Getting started](/bluetooth-bridge/getting-started.html) |
| run it with a controller | [Installation](/bluetooth-bridge/installation.html), then [Hardware](/bluetooth-bridge/hardware.html) |
| see sensors in Home Assistant | [Sensors and beacons](/bluetooth-bridge/sensors.html), [Home Assistant](/bluetooth-bridge/home-assistant.html) |
| connect to a device, read and write GATT | [Connections, GATT and pairing](/bluetooth-bridge/connections.html) |
| script it or build on its topics | [MQTT API](/bluetooth-bridge/mqtt.html) |
| change a setting | [Configuration](/bluetooth-bridge/configuration.html) and the [reference](/bluetooth-bridge/config-reference.html) |
| embed the stack in Rust | [Library overview](/bluetooth-bridge/library.html) |
| understand how it works | [Architecture](/bluetooth-bridge/architecture.html) |
| fix a problem | [Troubleshooting and FAQ](/bluetooth-bridge/troubleshooting.html) |

## Status

bluetooth-bridge is at 0.x. Version 0.1.0 is Bluetooth LE; Bluetooth Mesh is
in progress on `main` as a library. Everything is tested in CI against
Bumble's virtual controller, but **no release has been tested on real
hardware yet**. Pages that describe something only real hardware can
confirm say so.

Bluetooth® is a registered trademark of the Bluetooth SIG, Inc. This
project is not affiliated with or qualified by the Bluetooth SIG.

## Terms used in these docs

- **Controller**: the Bluetooth chip, on a board, a USB dongle or a UART. It
  runs the radio and the link layer and speaks **HCI** (the Host Controller
  Interface) to the host.
- **Host**: the software above HCI. Usually that is the kernel and BlueZ; with
  bluetooth-bridge it is this stack, running as one process.
- **HCI user channel**: a Linux socket that gives one program exclusive,
  raw access to a controller the kernel's driver has set up.
- **H4**: HCI over a byte stream (a UART, or TCP).
- **Address**: six bytes, written `C0:11:22:33:44:55`, public or random.
  Devices with privacy use **resolvable private addresses** that change
  every few minutes; with the device's **IRK** they resolve to its stable
  **identity** address.
- **Advertisement**: a broadcast packet. Sensors and beacons put their
  readings in advertisements; nothing needs to connect to them.
- **GATT**: the attribute protocol used over a connection: services,
  characteristics, reads, writes and notifications.
- **Bond**: the keys two devices keep after pairing, so they can encrypt
  again without pairing.
