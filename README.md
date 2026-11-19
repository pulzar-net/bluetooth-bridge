# bluetooth-bridge

A Bluetooth host stack and MQTT bridge in Rust, maintained by
[Pulzar](https://pulzr.net). MIT licensed.

It drives a Bluetooth controller directly over HCI: the Linux HCI user
channel, H4 on a serial port, or H4 over TCP. There is no BlueZ and no D-Bus,
so the same features work on every board, from a Raspberry Pi's on-board chip
to a USB dongle on an OpenWrt router. It is a set of library crates you can
embed, and a standalone bridge that speaks MQTT with Home Assistant discovery
and a plain JSON topic scheme.

**Status: 0.1.0, first milestone (Bluetooth LE), not yet tested on
hardware.** Every role, pairing method and GATT operation runs end to end in
CI against [Bumble](https://github.com/google/bumble)'s virtual controller;
bench testing on real controllers is next.

## What it does

| Area | Supported |
|---|---|
| Transports | HCI user channel (Linux, after the kernel driver loads the chip's firmware), H4 over UART, H4 over TCP |
| Controller discovery | version, manufacturer, supported commands, LMP and LE features, LE states, buffers, advertising sets, list sizes, data length; every feature checks before it asks |
| Observer | passive and active scanning, legacy and extended reports, coded PHY, fragmented report reassembly, periodic advertising sync, filter accept list, duplicate filtering done by the host (off, on change, or on change plus a heartbeat) |
| Advertising data | every AD type in the SIG's assigned numbers named and parsed into typed fields; company, UUID, appearance and URI scheme names from the SIG's own published data |
| Beacons and sensors | iBeacon, AltBeacon, Eddystone (UID, URL, TLM, encrypted TLM, EID), BTHome v2 including decryption, KKM KBeacon (sensor v1 and v2, encrypted frames, system), Ruuvi (through the `ruuvi-sensor-protocol` crate) |
| Broadcaster | legacy advertising, extended advertising sets (up to the controller's count, 1650 octets), periodic advertising trains |
| Connections | central and peripheral; parameter updates (controller procedure as central, L2CAP request as peripheral); PHY update; data length extension; RSSI; remote features |
| L2CAP | LE signaling; LE Credit Based and enhanced Credit Based channels with real inbound flow control |
| ATT and GATT | client: MTU exchange, discovery (services, included services, characteristics, descriptors), read, long read, read by type, read multiple (fixed and variable), write, write without response, long and reliable writes, notifications and indications; server: a database built at run time with per-attribute security, client configuration kept for bonded peers, long writes, Service Changed and Database Hash |
| SMP | LE legacy pairing and LE Secure Connections; Just Works, Numeric Comparison, Passkey Entry (either side typing, or both), Out of Band; every IO capability; key distribution; bonding with a persistent key store (mode 0600, atomic writes); re-encryption with stored keys; debug-key and reflected-key rejection |
| Privacy | resolvable private addresses resolved to identities from stored IRKs (bonded, or entered by hand for tags), so a device with a rotating address stays one device |

Later milestones are designed in [docs/roadmap.md](docs/roadmap.md):
Bluetooth Mesh, Classic BR/EDR (inquiry, SDP, RFCOMM), direction finding and
channel sounding.

## Crates

| Crate | What it does |
|---|---|
| `bluetooth-numbers` | the Bluetooth SIG's Assigned Numbers as lookup functions, generated at build time from the SIG's public repository (a git submodule), never typed in |
| `bluetooth-adv` | advertising data: every AD type, and the beacon and sensor formats; no `unsafe`, never panics on any input |
| `bluetooth-host` | the host stack |
| `bluetooth-bridge` | the standalone MQTT bridge |

HCI commands and events are encoded and decoded by
[`bt-hci`](https://github.com/embassy-rs/bt-hci) (Embassy's HCI types), and
the user channel socket comes from `bt-hci-linux`. Cryptography is
RustCrypto's (`aes`, `cmac`, `ccm`, `p256`, `md-5`).

## Running the bridge

```sh
git clone --recurse-submodules https://github.com/pulzar-net/bluetooth-bridge
cargo build --release
cp config.example.toml /etc/bluetooth-bridge/config.toml   # set adapter.transport
bluetooth-bridge --config /etc/bluetooth-bridge/config.toml
```

With the HCI user channel the bridge owns the controller: stop `bluetoothd`
(and anything else using `hci0`) first, and give the bridge `CAP_NET_ADMIN`.
A UART controller with no kernel driver is opened with
`transport = "serial:/dev/ttyACM0:1000000"`.

`bluetooth-bridge probe hci0` names the controller and its features as JSON.

### Topics

Under `mqtt.base_topic` (`bluetooth`):

| Topic | What |
|---|---|
| `bluetooth/bridge/state` | `{"state":"online"}` or `offline` (retained; the will) |
| `bluetooth/bridge/info` | the controller and its capabilities (retained) |
| `bluetooth/scan/<ADDRESS>` | each advertisement after duplicate filtering: RSSI, PHYs, TX power, SID, flags, raw data, every parsed field, decoded beacons |
| `bluetooth/device/<ADDRESS>` | a device's decoded readings, for Home Assistant |
| `bluetooth/bridge/event` | connections, pairing, notifications, GATT writes, periodic reports |
| `bluetooth/bridge/request/<op>` | requests, JSON, with an optional `transaction` |
| `bluetooth/bridge/response/<op>` | `{"transaction", "status": "ok" or "error", "data" or "error"}` |

`<ADDRESS>` is twelve upper-case hex digits (`BC5729000001`), the identity
when a private address resolved.

Requests: `info`, `scan/start` (`config`), `scan/stop`, `connect`
(`address`, `params`), `disconnect`, `connections`, `connection/params`,
`connection/phy`, `connection/data_length`, `connection/rssi`, `gatt/mtu`,
`gatt/discover`, `gatt/read`, `gatt/write` (`value` hex,
`without_response`), `gatt/subscribe`, `pair`, `secure`, `unpair`, `bonds`
(never keys), `advertise/start` (`params`, `data`, `scan_response`),
`advertise/data`, `advertise/stop`, `periodic/start`, `periodic/stop`,
`periodic/sync`, `periodic/terminate`, `server/add` (a service definition),
`server/set` (`notify` to push it to subscribers), `server/get`.

Example:

```sh
mosquitto_pub -t bluetooth/bridge/request/connect -m '{"address":"C0:11:22:33:44:55/random","transaction":"1"}'
mosquitto_pub -t bluetooth/bridge/request/gatt/read -m '{"handle":64,"attribute":3}'
```

## Testing

```sh
python -m venv .venv && .venv/bin/pip install -r tests/bumble/requirements.txt
BUMBLE_PYTHON=.venv/bin/python cargo test --workspace
```

- **End to end, against Bumble** (`crates/bluetooth-host/tests/bumble.rs`,
  `crates/bluetooth-bridge/tests/mqtt.rs`): the host under test reaches a
  Bumble virtual controller over H4 on TCP, exactly as it would a real one,
  and `tests/bumble/peer.py` scripts the peer on the same simulated link:
  scanning, advertising, periodic sync, central and peripheral GATT, L2CAP
  channels both ways, every pairing method in both roles with bonding and
  re-encryption, private address resolution, and the bridge over MQTT.
- **HCI replay** (`tests/replay.rs`): a scripted controller answers commands
  and sends exact event bytes, for what Bumble's coarse radio model cannot
  carry (SIDs, legacy bits, fragmented reports, scan responses) and for a
  Bluetooth 4 controller's limits. Recorded traffic from real chips goes
  here.
- **Crypto** against the Core Specification's test vectors (Vol 3, Part H,
  Appendix D).
- **Fuzzing** (`fuzz/`, cargo-fuzz) of every parser that reads the air or
  the controller, with a stable smoke pass on every `cargo test --features
  fuzzing`.
- **Budgets**: under 8 MB resident scanning a busy site (5,000 advertisers,
  200,000 reports), under 3 MB for the static bridge binary; both checked in
  CI, with static aarch64 and mipsel musl builds tested under qemu.

## Hardware for a bench

- A **Bluetooth 5 USB dongle with an in-tree Linux driver**: one on a
  Realtek RTL8761BU (btusb loads `rtl8761bu_fw`), such as the TP-Link UB500
  or ASUS USB-BT500, gives extended advertising, 2M and coded PHY and DLE.
- A **Nordic nRF52840 Dongle (PCA10059)** running Zephyr's `hci_uart` (or
  `hci_usb`) sample as a full-feature controller over H4, and as a second,
  scriptable test peer: periodic advertising, coded PHY, and later direction
  finding with an antenna board.

## License

MIT. The assigned numbers come from the Bluetooth SIG's public repository
and are the SIG's.
