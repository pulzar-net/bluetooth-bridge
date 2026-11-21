---
title: "bluetooth-adv"
description: "Bluetooth LE advertising data and the beacon and sensor formats carried in it."
---

Bluetooth LE advertising data and the beacon and sensor formats carried in
it. No I/O, no `unsafe`, never panics on any input. [crates.io](https://crates.io/crates/bluetooth-adv), [docs.rs](https://docs.rs/bluetooth-adv), [API docs for `main`](https://oss.pulzr.net/bluetooth-bridge/api/bluetooth_adv/index.html).

- `Advertisement::parse` parses advertising data (and `extend` adds a scan
  response) into every AD type, named and typed: flags, names, UUIDs,
  service data, manufacturer data, TX power, appearance, URIs and the rest.
- `beacon::decode` finds the beacons and sensor frames in an advertisement:
  iBeacon, AltBeacon, Eddystone, BTHome v2, KKM and Ruuvi. A `Context`
  carries the advertiser's address and any BTHome bind keys or KKM
  passwords, for encrypted frames.
- `Beacon::readings` flattens a frame into readings with stable keys and
  units (`temperature` in °C), which is what the bridge publishes.

The README's [library example](https://github.com/pulzar-net/bluetooth-bridge#use-it-as-a-library)
decodes a BTHome advertisement; it runs as a doctest in CI.

Feature `serde` (default) serializes everything, which is how the bridge
produces its `scan/` payloads.
