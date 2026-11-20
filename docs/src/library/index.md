# The library crates

bluetooth-bridge is built as a stack of library crates. The bridge binary is
the thinnest layer on top; everything else can be used without it.

| Crate | Layer | Use it to |
|---|---|---|
| [bluetooth-host](bluetooth-host.md) | the host stack | scan, advertise, connect, use GATT and pair from Rust, on any controller |
| [bluetooth-adv](bluetooth-adv.md) | advertising data | parse advertisements and decode beacons and sensors, with no I/O |
| [bluetooth-numbers](bluetooth-numbers.md) | assigned numbers | name companies, UUIDs, appearances and AD types |
| [bluetooth-mesh](bluetooth-mesh.md) | Bluetooth Mesh | provision and control mesh nodes (work in progress) |
| [bluetooth-bridge](bluetooth-bridge.md) | MQTT bridge | run or embed the bridge itself |

The [API documentation](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_host/index.html) covers every public
item.

## Depending on the crates

The crates are not published on crates.io yet. Depend on a release tag:

```toml
[dependencies]
bluetooth-host = { git = "https://github.com/pulzar-net/bluetooth-bridge", tag = "v0.1.0" }
```

Every crate shares the workspace version and is released together. While
the project is at 0.x, minor versions may break the API; the
[changelog](../changelog.md) says what changed.

## Conventions shared by every crate

- **No `unsafe`.** The workspace lints forbid `unsafe` code.
- **No panics on input.** Everything parsed from the air or the controller
  is bounds checked and fuzzed; a malformed packet is an error value, never
  a panic.
- **Adopted, not rewritten.** HCI commands and events come from Embassy's
  [bt-hci](https://github.com/embassy-rs/bt-hci) crate, cryptography from
  RustCrypto, Ruuvi decoding from `ruuvi-sensor-protocol`, and the
  assigned numbers from the Bluetooth SIG's own data.
