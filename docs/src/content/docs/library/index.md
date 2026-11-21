---
title: "The library crates"
description: "bluetooth-bridge is built as a stack of library crates."
---

bluetooth-bridge is built as a stack of library crates. The bridge binary is
the thinnest layer on top; everything else can be used without it.

| Crate | Layer | Use it to |
|---|---|---|
| [bluetooth-host](/bluetooth-bridge/library/bluetooth-host.html) | the host stack | scan, advertise, connect, use GATT and pair from Rust, on any controller |
| [bluetooth-adv](/bluetooth-bridge/library/bluetooth-adv.html) | advertising data | parse advertisements and decode beacons and sensors, with no I/O |
| [bluetooth-numbers](/bluetooth-bridge/library/bluetooth-numbers.html) | assigned numbers | name companies, UUIDs, appearances and AD types |
| [bluetooth-mesh-stack](/bluetooth-bridge/library/bluetooth-mesh-stack.html) | Bluetooth Mesh | provision, configure and control mesh nodes |
| [bluetooth-bridge](/bluetooth-bridge/library/bluetooth-bridge.html) | MQTT bridge | run or embed the bridge itself |

The [API documentation](https://oss.pulzr.net/bluetooth-bridge/api/bluetooth_host/index.html) covers every public
item.

## Depending on the crates

Every crate is on [crates.io](https://crates.io/search?q=bluetooth-bridge), with its API on docs.rs:

```sh
cargo add bluetooth-host
```

Every crate shares the workspace version and is released together. While
the project is at 0.x, minor versions may break the API; the
[changelog](/bluetooth-bridge/changelog.html) says what changed.

## Conventions shared by every crate

- **No `unsafe`.** The workspace lints forbid `unsafe` code.
- **No panics on input.** Everything parsed from the air or the controller
  is bounds checked and fuzzed; a malformed packet is an error value, never
  a panic.
- **Adopted, not rewritten.** HCI commands and events come from Embassy's
  [bt-hci](https://github.com/embassy-rs/bt-hci) crate, cryptography from
  RustCrypto, Ruuvi decoding from `ruuvi-sensor-protocol`, and the
  assigned numbers from the Bluetooth SIG's own data.
