---
title: "bluetooth-bridge (crate)"
description: "The bridge as a library: the same code as the binary."
---

The bridge as a library: the same code as the binary. [crates.io](https://crates.io/crates/bluetooth-bridge), [docs.rs](https://docs.rs/bluetooth-bridge), [API docs for `main`](https://oss.pulzr.net/bluetooth-bridge/api/bluetooth_bridge/index.html).

- `run(config)` runs the bridge until it is stopped.
- `Config` is the configuration file; `Config::load` and `Config::parse`
  read one with every check the binary applies.
- `bridge::request` runs one MQTT request against a `Host`, if you want
  the same request vocabulary in your own transport.
- `ha` builds the Home Assistant discovery messages.

The [MQTT API](/bluetooth-bridge/mqtt.html) and [configuration reference](/bluetooth-bridge/config-reference.html)
document the behavior.
