# bluetooth-bridge (crate)

The bridge as a library: the same code as the binary. [API docs](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_bridge/index.html).

- `run(config)` runs the bridge until it is stopped.
- `Config` is the configuration file; `Config::load` and `Config::parse`
  read one with every check the binary applies.
- `bridge::request` runs one MQTT request against a `Host`, if you want
  the same request vocabulary in your own transport.
- `ha` builds the Home Assistant discovery messages.

The [MQTT API](../mqtt.md) and [configuration reference](../config-reference.md)
document the behavior.
