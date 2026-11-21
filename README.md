# bluetooth-bridge

[![CI](https://github.com/pulzar-net/bluetooth-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/pulzar-net/bluetooth-bridge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/pulzar-net/bluetooth-bridge)](https://github.com/pulzar-net/bluetooth-bridge/releases/latest)
[![crates.io](https://img.shields.io/crates/v/bluetooth-host.svg)](https://crates.io/crates/bluetooth-host)
[![docs.rs](https://img.shields.io/docsrs/bluetooth-host)](https://docs.rs/bluetooth-host)
[![Docs](https://img.shields.io/badge/docs-oss.pulzr.net-blue)](https://oss.pulzr.net/bluetooth-bridge/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](Cargo.toml)

A Bluetooth host stack over raw HCI and a Bluetooth LE to MQTT bridge,
written in Rust. It drives a Bluetooth controller directly, with no BlueZ
and no D-Bus: the Linux HCI user channel, H4 on a serial port, or H4 over
TCP. The bridge scans, decodes beacons and sensors (BTHome, Ruuvi,
iBeacon, Eddystone and more), publishes them to MQTT with Home Assistant
discovery, and exposes connections, GATT, pairing and advertising as MQTT
requests. It is one static binary of under 3 MB that scans a busy site in
under 8 MB of memory, so it fits on routers and small gateways as well as
on a Raspberry Pi or a server. The same stack is a set of library crates
for anyone building Bluetooth software in Rust.

It exists because a Bluetooth host on Linux usually means BlueZ, whose
features and behavior depend on the kernel and BlueZ version of each board,
and there was no complete Bluetooth LE host in Rust that runs on HCI
directly, the same way on every board.

**[Documentation](https://oss.pulzr.net/bluetooth-bridge/)** |
**[Quick start](#quick-start)** |
**[Hardware](#supported-hardware)** |
**[MQTT API](https://oss.pulzr.net/bluetooth-bridge/mqtt.html)** |
**[Library](#use-it-as-a-library)** |
**[Changelog](CHANGELOG.md)**

## Status

bluetooth-bridge is **0.x and young**. Version 0.1.0 is Bluetooth LE; 0.2.0
adds the first part of Bluetooth Mesh. Every
role, pairing method and GATT operation is tested in CI against
[Bumble](https://github.com/google/bumble)'s virtual controller, but **it
has not yet been tested on real hardware**. Expect rough edges and breaking
changes between 0.x releases.

| Feature | State |
|---|---|
| Transports: Linux HCI user channel, H4 over UART, H4 over TCP | done in 0.1.0 |
| Scanning: passive and active, legacy and extended, coded PHY, periodic advertising sync, duplicate filtering by the host | done in 0.1.0 |
| Advertising data: every AD type, names from the Bluetooth SIG's assigned numbers | done in 0.1.0 |
| Beacons and sensors: iBeacon, AltBeacon, Eddystone, BTHome v2 (with decryption), Ruuvi, KKM | done in 0.1.0 |
| Advertising: legacy, extended sets, periodic trains | done in 0.1.0 |
| Connections as central and peripheral; parameter, PHY and data length updates | done in 0.1.0 |
| L2CAP credit-based channels; GATT client and server | done in 0.1.0 |
| Pairing: legacy and Secure Connections, every method and IO capability, bonding | done in 0.1.0 |
| Privacy: private addresses resolved to identities | done in 0.1.0 |
| Home Assistant MQTT discovery for decoded sensors | done in 0.1.0 |
| Bluetooth Mesh: the bridge as provisioner over the advertising bearer; the GATT proxy in the library | done in 0.2.0 |
| Bluetooth Mesh, the rest: PB-GATT, IV update, relay, friendship, more models | in progress |
| Testing on real controllers | in progress |
| Classic BR/EDR (inquiry, SDP, RFCOMM) | planned |
| Direction finding (AoA, AoD) and channel sounding | planned |
| LE Audio | not planned |

## Supported hardware

A Bluetooth controller is a chip with HCI firmware: built into a board or
on a USB dongle or UART. **Expected** means the controller speaks standard
HCI and the stack checks every feature before using it, but nobody has
reported it working yet. If you try one, please
[tell us how it went](https://github.com/pulzar-net/bluetooth-bridge/issues/new?template=device.yml).

| Controller | Connection | Firmware | State |
|---|---|---|---|
| Realtek RTL8761B USB dongles (TP-Link UB500, ASUS USB-BT500) | `hci0` (btusb) | `rtl8761bu_fw`, loaded by the kernel | expected; Bluetooth 5 with extended advertising, 2M and coded PHY |
| Nordic nRF52840 Dongle | H4 over USB serial | Zephyr `hci_uart` or `hci_usb` sample | expected; full Bluetooth 5 feature set |
| Raspberry Pi 3, 4, 5 built-in | `hci0` | Broadcom/Cypress firmware, loaded by the kernel | expected; Bluetooth 4.1 to 5.0 features |
| Intel AX200, AX210 and other btusb controllers | `hci0` | loaded by the kernel | expected |
| Bluetooth 4.0 dongles (CSR8510 and similar) | `hci0` | | expected; no extended advertising or coded PHY |
| Controllers that need vendor setup a kernel driver does not do, over raw UART | | | unsupported |

Sensors: BTHome v2 devices (Shelly BLU, and sensors with BTHome firmware such
as the ATC/pvvx firmware for Xiaomi thermometers), Ruuvi tags, KKM beacons,
iBeacon, AltBeacon and Eddystone beacons are decoded; any other advertiser
is published with its parsed advertising data. The
[hardware page](https://oss.pulzr.net/bluetooth-bridge/hardware.html)
has the details.

## Quick start

From nothing to a sensor in Home Assistant, on 64-bit Linux (x86_64 or
aarch64) with a Bluetooth controller (`hci0`). You need an MQTT broker (for
example Mosquitto) that Home Assistant's MQTT integration already uses.

**1. Download the release and check its checksum.**

<!-- quickstart:download -->
```sh
VERSION=0.2.0
ARCH=$(uname -m)   # x86_64 or aarch64
BASE=https://github.com/pulzar-net/bluetooth-bridge/releases/download/v$VERSION
curl -fsSLO "$BASE/bluetooth-bridge-$ARCH-linux-musl"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
sudo install -m 0755 "bluetooth-bridge-$ARCH-linux-musl" /usr/local/bin/bluetooth-bridge
bluetooth-bridge --version
```

**2. Free the controller.** The bridge drives the controller itself through
the HCI user channel, so BlueZ must let go of it:

```sh
sudo systemctl stop bluetooth
sudo bluetooth-bridge probe hci0
```

`probe` prints the controller and its features as JSON.

**3. Write a minimal configuration** to `/etc/bluetooth-bridge/config.toml`.
Only `adapter.transport` is required; everything else has a default.

<!-- quickstart:config -->
```toml
[adapter]
transport = "hci0"

[mqtt]
host = "localhost"   # your broker
```

**4. Run it.** It needs `CAP_NET_ADMIN` for the user channel; `sudo` gives
it that.

<!-- quickstart:run -->
```sh
sudo bluetooth-bridge --config /etc/bluetooth-bridge/config.toml
```

**5. Bring a sensor in range.** There is no pairing for broadcast sensors:
a BTHome or Ruuvi sensor appears within seconds, in Home Assistant under
**Settings > Devices & services > MQTT**, and on MQTT:

```sh
mosquitto_sub -h localhost -t 'bluetooth/device/#' -v
```

No controller to spare? The [getting started guide](https://oss.pulzr.net/bluetooth-bridge/getting-started.html)
runs the same steps against Bumble's virtual controller. To run the bridge
as a service, see [installation](#installation).

## Installation

- **Release binaries.** Each [release](https://github.com/pulzar-net/bluetooth-bridge/releases)
  has static Linux binaries for `x86_64`, `aarch64` (Raspberry Pi 3 and newer
  with a 64-bit OS) and `mipsel` (MT7621 and MT7628 routers), with a
  `SHA256SUMS` file. They have no runtime dependencies.
- **From source**, with Rust 1.89 or newer. The Bluetooth SIG's assigned
  numbers are a git submodule, so clone with `--recurse-submodules`, or use
  `cargo install --locked --git https://github.com/pulzar-net/bluetooth-bridge bluetooth-bridge`.
- **systemd**: a hardened unit is in [`contrib/systemd/`](contrib/systemd/bluetooth-bridge.service).
- **OpenWrt**: a procd init script is in [`contrib/openwrt/`](contrib/openwrt/bluetooth-bridge.init).

The [installation guide](https://oss.pulzr.net/bluetooth-bridge/installation.html)
covers each one step by step.

## Configuration

The bridge reads one TOML file, `/etc/bluetooth-bridge/config.toml` by
default (`--config FILE` to change it):

| Table | What it sets |
|---|---|
| `[adapter]` | the transport (`hci0`, `serial:PATH:BAUD`, `tcp:HOST:PORT`), name, pairing capabilities and policy, address |
| `[mqtt]` | broker, credentials (password from a file), client id, base topic |
| `[scan]` | active or passive, interval and window, coded PHY, duplicate filtering, address allow list, minimum RSSI |
| `[homeassistant]` | discovery on or off, discovery prefix, Home Assistant's status topic |
| `[data]` | the data directory: bonds and the bridge's own identity |
| `[[bthome_keys]]`, `[[kkm_passwords]]`, `[[irks]]` | keys for encrypted sensors and for resolving private addresses |
| `[[gatt_services]]`, `[[advertising]]` | GATT services the bridge serves and advertising sets it starts |
| `[mesh]` | Bluetooth Mesh provisioner (since 0.2.0) |

Unknown keys are an error, so a typo stops the bridge at startup. Every key,
its type and default are in the
[configuration reference](https://oss.pulzr.net/bluetooth-bridge/config-reference.html),
which is generated from the code. [`config.example.toml`](config.example.toml)
shows them all. Log verbosity comes from `RUST_LOG` (default `info`).

## MQTT API

Everything lives under a base topic, `bluetooth` by default. Payloads are
JSON. `<ADDRESS>` is twelve upper-case hex digits (`BC5729000001`): the
device's identity address when its private address resolved.

| Topic | Direction | What |
|---|---|---|
| `bluetooth/bridge/state` | out, retained | `{"state":"online"}` or `{"state":"offline"}` (also the last will) |
| `bluetooth/bridge/info` | out, retained | the controller, its version and features |
| `bluetooth/scan/<ADDRESS>` | out | each advertisement after duplicate filtering: RSSI, PHYs, raw data, every parsed field, decoded beacons |
| `bluetooth/device/<ADDRESS>` | out | a sensor's decoded readings, for example `{"temperature":25.06,"humidity":50.55,"rssi":-50,"last_seen":1795138399393}` |
| `bluetooth/bridge/event` | out | connections, pairing, notifications, GATT writes, periodic reports |
| `bluetooth/bridge/request/<op>` | in | `scan/start`, `connect`, `gatt/read`, `gatt/write`, `pair`, `advertise/start`, `server/add` and 22 more |
| `bluetooth/bridge/response/<op>` | out | `{"status":"ok","data":...}` or `{"status":"error","error":"..."}`, with the request's `transaction` |

Keys never appear on MQTT; `bonds` lists who is bonded, not the keys. The
[MQTT reference](https://oss.pulzr.net/bluetooth-bridge/mqtt.html)
has every request and payload with examples.

## Use it as a library

The bridge is a thin layer over library crates you can use on their own.

| Crate | What it is | |
|---|---|---|
| [`bluetooth-host`](crates/bluetooth-host) | the host stack: transports, scanning, advertising, connections, L2CAP, ATT and GATT, SMP, privacy, bonds | [crates.io](https://crates.io/crates/bluetooth-host), [docs.rs](https://docs.rs/bluetooth-host) |
| [`bluetooth-adv`](crates/bluetooth-adv) | advertising data: every AD type, and beacon and sensor formats; no I/O | [crates.io](https://crates.io/crates/bluetooth-adv), [docs.rs](https://docs.rs/bluetooth-adv) |
| [`bluetooth-numbers`](crates/bluetooth-numbers) | the Bluetooth SIG's assigned numbers as lookups, generated from the SIG's repository | [crates.io](https://crates.io/crates/bluetooth-numbers), [docs.rs](https://docs.rs/bluetooth-numbers) |
| [`bluetooth-mesh-stack`](crates/bluetooth-mesh-stack) | Bluetooth Mesh: provisioning, configuration, the advertising and GATT proxy bearers | [crates.io](https://crates.io/crates/bluetooth-mesh-stack), [docs.rs](https://docs.rs/bluetooth-mesh-stack) |
| [`bluetooth-bridge`](crates/bluetooth-bridge) | the MQTT bridge, as a binary and a library | [crates.io](https://crates.io/crates/bluetooth-bridge), [docs.rs](https://docs.rs/bluetooth-bridge) |

```sh
cargo add bluetooth-adv            # or bluetooth-host, bluetooth-numbers, bluetooth-mesh-stack
cargo install bluetooth-bridge     # the bridge binary, built from source
```

This example decodes a BTHome v2 temperature and humidity advertisement,
the kind a sensor broadcasts, and prints `bt_home temperature: 25.06 °C` and
`bt_home humidity: 50.55 %`. The host stack's own example (scan with a
controller) is in the [library guide](https://oss.pulzr.net/bluetooth-bridge/library/bluetooth-host.html).

```rust
use bluetooth_adv::beacon::{self, Context};
use bluetooth_adv::Advertisement;

// Flags, then BTHome service data: temperature 25.06 °C, humidity 50.55 %.
let data = [
    0x02, 0x01, 0x06,
    0x0a, 0x16, 0xd2, 0xfc, 0x40, 0x02, 0xca, 0x09, 0x03, 0xbf, 0x13,
];
let adv = Advertisement::parse(&data);
for b in beacon::decode(&adv, &Context::default()) {
    for r in b.readings() {
        println!("{} {}: {} {}", b.format(), r.key, r.value, r.unit);
    }
}
# let readings = beacon::decode(&adv, &Context::default())[0].readings();
# assert_eq!((readings[0].key.as_str(), readings[0].value), ("temperature", 25.06));
# assert_eq!((readings[1].key.as_str(), readings[1].value), ("humidity", 50.55));
```

The [library guide](https://oss.pulzr.net/bluetooth-bridge/library/index.html)
covers each crate, including the host stack, and the
[API docs](https://oss.pulzr.net/bluetooth-bridge/api/bluetooth_host/index.html)
cover every item.

## Architecture

```text
 Home Assistant, Node-RED, scripts
                │  MQTT (JSON, Home Assistant discovery)
┌───────────────┴───────────────────────────────────────┐
│ bluetooth-bridge   topics, requests, readings,        │
│                    discovery                          │
├───────────────────────────────────────────────────────┤
│ bluetooth-host     scanner, advertiser, connections,  │
│                    L2CAP, ATT/GATT, SMP, privacy,     │
│                    bonds                              │
├────────────────────────┬──────────────────────────────┤
│ bluetooth-adv          │ bt-hci (HCI commands and     │
│ bluetooth-numbers      │ events, from Embassy)        │
└────────────────────────┴───────────────┬──────────────┘
                                         │ HCI user channel, H4 serial, H4 TCP
                  Bluetooth controller (or Bumble's virtual controller)
```

The controller runs the radio and the link layer. Everything above HCI runs
in the host, with no BlueZ and no kernel Bluetooth stack in the path. The
[architecture page](https://oss.pulzr.net/bluetooth-bridge/architecture.html)
explains the layers and the design rules (no `unsafe`, no panics on radio
input, bounded memory).

## Compared with other projects

| | bluetooth-bridge | [BlueZ](https://www.bluez.org) | Home Assistant's [Bluetooth integration](https://www.home-assistant.io/integrations/bluetooth/) |
|---|---|---|---|
| What it is | host stack on raw HCI, and an MQTT bridge | the Linux Bluetooth stack, with a D-Bus API | Home Assistant's use of BlueZ, with ESPHome proxies |
| Language and runtime | Rust, one static binary | C, a system daemon and the kernel's stack | Python |
| Bluetooth Classic | planned | yes, complete | through BlueZ |
| Same behavior on every board | yes: it does not depend on the kernel's or BlueZ's version | depends on both | depends on BlueZ |
| Interface | MQTT, Home Assistant discovery, Rust API | D-Bus, command-line tools | Home Assistant |
| Shares the controller | no: it owns it | yes, with every program on the system | through BlueZ |
| Maturity | 0.x, not yet hardware-tested | mature, the Linux standard | mature, very widely used |

**Pick BlueZ** if other programs on the machine need Bluetooth too, if you
need Classic profiles (audio, keyboards, serial) today, or if you want the
standard Linux tools. **Pick Home Assistant's own integration** if Home
Assistant runs next to the radio and its device support covers you.
**Pick bluetooth-bridge** if you want Bluetooth LE on a router or gateway
where BlueZ is missing, old or inconsistent, as MQTT for any consumer, or as
a Rust library that behaves the same on every board.

## Roadmap

- **Next:** the rest of Bluetooth Mesh (0.2.0 provisions, configures and
  switches nodes over the advertising bearer and through a GATT proxy; next
  come PB-GATT, IV update, relay, friendship, more models), and the first
  reports from real hardware.
- **After that:** Classic BR/EDR (inquiry, Secure Simple Pairing, SDP,
  RFCOMM), then direction finding.

The [roadmap page](https://oss.pulzr.net/bluetooth-bridge/roadmap.html)
has the design for each. Questions go in [Discussions](https://github.com/pulzar-net/bluetooth-bridge/discussions); bugs and requests in [issues](https://github.com/pulzar-net/bluetooth-bridge/issues).

## Contributing

Contributions are welcome, from hardware reports to code. The whole stack
can be developed and tested without hardware, against Bumble. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, fuzz and send a
change, and [the code of conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/pulzar-net/bluetooth-bridge/security/advisories/new),
never in a public issue. See [SECURITY.md](SECURITY.md) for what to include
and how fast we respond, and the
[security model](https://oss.pulzr.net/bluetooth-bridge/security.html)
for what the bridge protects.

## License

MIT. See [LICENSE](LICENSE).

The assigned numbers are generated at build time from the Bluetooth SIG's
public repository and remain the SIG's; they are not copied into this
repository. Bluetooth® is a registered trademark of the Bluetooth SIG, Inc.
This project is not affiliated with or qualified by the Bluetooth SIG.

## Maintained by Pulzar

bluetooth-bridge is maintained by [Pulzar](https://pulzr.net), which uses it
in its own gateways. It is developed in the open, for anyone to use.
