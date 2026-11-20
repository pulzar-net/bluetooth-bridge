# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Second milestone, in progress: Bluetooth Mesh.

### Added

- `bluetooth-numbers`: Mesh model opcodes and model identifiers.
- `bluetooth-mesh-stack`, new (named for crates.io, where `bluetooth-mesh` is taken):
  - The security toolbox (s1, k1 to k4) and network PDU encryption and
    obfuscation, checked against the specification's sample data.
  - Lower and upper transport: segmentation and reassembly, block
    acknowledgments, application and device key encryption.
  - Provisioning on both sides (ECDH P-256, every authentication method)
    over PB-ADV, and the advertising bearer's beacons.
  - The access layer: Composition Data, the Configuration models a
    provisioner needs, Generic OnOff and Level.
  - A runtime that provisions, configures and controls nodes, and runs as
    a node, on any bearer: the advertising bearer through `bluetooth-host`,
    or GATT through the Mesh Proxy service (`ProxyBearer` as the client,
    `ProxyServer` on a node, with proxy filters).
  - End to end in CI on two Bumble controllers: provisioning, configuration
    and control over advertising, and control through a proxy.
- `bluetooth-bridge`: `[mesh] enabled` makes the bridge a mesh's provisioner
  on its own controller; requests `mesh/network`, `mesh/unprovisioned`,
  `mesh/provision`, `mesh/configure` and `mesh/onoff`, and events on
  `<base>/mesh/event`.
- `bluetooth-host`: `ScanConfig::always_report`, AD types reported every time
  whatever the duplicate filter says (Mesh's retransmissions are identical).

### Fixed

- Home Assistant: each bridge on a broker is its own device, named for its
  base topic (`bluetooth_bridge_<base>`); the default `bluetooth` keeps the
  `bluetooth_bridge` id, so an existing installation keeps its device. Two
  bridges used to share one.

## [0.1.0] - 2026-11-19

First milestone: Bluetooth LE.

### Added

- `bluetooth-numbers`: the SIG's assigned numbers (company identifiers;
  service, characteristic, descriptor, unit, member and SDO UUIDs; AD types;
  appearance; URI schemes; core versions; PSMs; format types), generated from
  the SIG's public repository.
- `bluetooth-adv`: every AD type parsed; iBeacon, AltBeacon, Eddystone, BTHome
  v2 with decryption, KKM KBeacon, Ruuvi.
- `bluetooth-host`: HCI over the Linux user channel, H4 serial and H4 TCP;
  capability discovery; observer with host-side duplicate filtering, extended
  report reassembly, periodic sync and address resolution; legacy, extended
  and periodic advertising; central and peripheral connections with
  parameter, PHY and data length updates; L2CAP signaling and credit-based
  channels; ATT, GATT client and run-time GATT server; SMP legacy and Secure
  Connections pairing with every association model, bonding and
  re-encryption; `probe`.
- `bluetooth-bridge`: MQTT bridge with Home Assistant discovery and requests
  for scanning, connections, GATT, pairing, advertising and the GATT server.

[Unreleased]: https://github.com/pulzar-net/bluetooth-bridge/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pulzar-net/bluetooth-bridge/releases/tag/v0.1.0
