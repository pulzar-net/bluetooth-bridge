# Changelog

All notable changes are listed here. The project follows semantic
versioning.

## 0.1.0 (unreleased)

First milestone: Bluetooth LE.

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
