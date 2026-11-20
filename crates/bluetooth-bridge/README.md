# bluetooth-bridge

[![crates.io](https://img.shields.io/crates/v/bluetooth-bridge.svg)](https://crates.io/crates/bluetooth-bridge)
[![docs.rs](https://img.shields.io/docsrs/bluetooth-bridge)](https://docs.rs/bluetooth-bridge)

A standalone Bluetooth LE to MQTT bridge on the `bluetooth_host` stack.

```sh
cargo install bluetooth-bridge
```

Advertisements go out parsed (every AD type, beacon formats decoded),
decoded sensor readings get Home Assistant discovery, and every GATT,
pairing and advertising operation is a request on MQTT. See
`bridge` for the topics.

Part of [bluetooth-bridge](https://github.com/pulzar-net/bluetooth-bridge), maintained by
[Pulzar](https://pulzr.net). See the [user guide](https://pulzar-net.github.io/bluetooth-bridge/), the
[library guide](https://pulzar-net.github.io/bluetooth-bridge/library/index.html) and the
[API documentation](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_bridge/index.html).

License: MIT.
