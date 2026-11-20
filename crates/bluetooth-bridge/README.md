# bluetooth-bridge

A standalone Bluetooth LE to MQTT bridge on the `bluetooth_host` stack.

Advertisements go out parsed (every AD type, beacon formats decoded),
decoded sensor readings get Home Assistant discovery, and every GATT,
pairing and advertising operation is a request on MQTT. See
`bridge` for the topics.

Part of [bluetooth-bridge](https://github.com/pulzar-net/bluetooth-bridge), maintained by
[Pulzar](https://pulzr.net). See the [user guide](https://pulzar-net.github.io/bluetooth-bridge/), the
[library guide](https://pulzar-net.github.io/bluetooth-bridge/library/index.html) and the
[API documentation](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_bridge/index.html).

License: MIT.
