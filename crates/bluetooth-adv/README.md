# bluetooth-adv

[![crates.io](https://img.shields.io/crates/v/bluetooth-adv.svg)](https://crates.io/crates/bluetooth-adv)
[![docs.rs](https://img.shields.io/docsrs/bluetooth-adv)](https://docs.rs/bluetooth-adv)

Bluetooth LE advertising data, parsed and decoded.

```sh
cargo add bluetooth-adv
```

`Advertisement::parse` reads the AD structures of an advertisement or
scan response (Core Specification Supplement, Part A) into typed fields,
naming companies, UUIDs and appearance from the SIG's assigned numbers
(`bluetooth_numbers`). `beacon::decode` then recognises beacon and
sensor formats inside it.

Nothing here panics on any input: advertisements come off the air from
devices nobody vetted, and every parser is fuzzed.

```rust
use bluetooth_adv::{Advertisement, beacon};
// Flags, then an iBeacon.
let data = hex::decode(
    "0201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000010002c5",
).unwrap();
let adv = Advertisement::parse(&data);
let beacons = beacon::decode(&adv, &beacon::Context::default());
assert!(matches!(beacons[0], beacon::Beacon::IBeacon(_)));
```

Part of [bluetooth-bridge](https://github.com/pulzar-net/bluetooth-bridge), maintained by
[Pulzar](https://pulzr.net). See the [user guide](https://pulzar-net.github.io/bluetooth-bridge/), the
[library guide](https://pulzar-net.github.io/bluetooth-bridge/library/index.html) and the
[API documentation](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_adv/index.html).

License: MIT.
