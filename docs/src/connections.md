# Connections, GATT and pairing

Beyond sensors, the bridge exposes the whole LE host over MQTT: it can
connect to devices as a central, read and write their GATT characteristics,
pair and bond, serve its own GATT services as a peripheral, and advertise.
Every operation is a [request](mqtt.md#requests-and-responses).

## Connecting and reading

Connect to a device by its address:

```sh
mosquitto_pub -t bluetooth/bridge/request/connect -m '{"address": "C0:11:22:33:44:55/random", "transaction": "1"}'
# bluetooth/bridge/response/connect {"status":"ok","data":{"handle":64,"params":{...}},"transaction":"1"}
```

The `handle` names the connection in later requests. Discover its services:

```sh
mosquitto_pub -t bluetooth/bridge/request/gatt/discover -m '{"handle": 64}'
```

The answer lists every service, characteristic and descriptor with its
attribute handle. Read one by handle (values are hex):

```sh
mosquitto_pub -t bluetooth/bridge/request/gatt/read -m '{"handle": 64, "attribute": 3}'
# {"status":"ok","data":{"value":"626174746572792d6c6576656c"}}
```

Write, with or without a response:

```sh
mosquitto_pub -t bluetooth/bridge/request/gatt/write -m '{"handle": 64, "attribute": 12, "value": "01"}'
mosquitto_pub -t bluetooth/bridge/request/gatt/write -m '{"handle": 64, "attribute": 12, "value": "01", "without_response": true}'
```

Long values (longer than the MTU) are read and written with the long
procedures automatically. Raise the MTU with `gatt/mtu` first for speed.

## Notifications

Subscribe to a characteristic by its value handle:

```sh
mosquitto_pub -t bluetooth/bridge/request/gatt/subscribe -m '{"handle": 64, "attribute": 12, "notify": true}'
```

Each notification then arrives on `bluetooth/bridge/event` as
`{"type": "notification", "handle": 64, "attribute": 12, "value": "..."}`.

## Pairing and bonds

```sh
mosquitto_pub -t bluetooth/bridge/request/pair -m '{"handle": 64}'
```

How pairing goes depends on `[adapter]`:

| Key | Effect |
|---|---|
| `io_capability` | what the bridge can do in pairing: `no_input_no_output` (default, Just Works), `display_only`, `display_yes_no`, `keyboard_only`, `keyboard_display` |
| `passkey` | a fixed six-digit passkey the bridge shows or types when a method needs one |
| `bonding` | keep the keys (default `true`) |
| `mitm` | require protection against a man in the middle (rules out Just Works) |
| `secure_connections_only` | refuse LE legacy pairing |

With bonding, keys are stored in the data directory, and `secure` on a later
connection encrypts with them instead of pairing again. `bonds` lists bonded
devices (never their keys) and `unpair` forgets one.

Every pairing method (Just Works, Numeric Comparison, Passkey Entry, Out of
Band) is implemented in both roles and tested against Bumble. Over MQTT,
the bridge shows or types its configured `passkey`; it cannot prompt a
person mid-pairing.

## Serving GATT

The bridge can be a peripheral with its own services. Define them in the
configuration (served from start) or add them at run time with `server/add`:

```toml
[[gatt_services]]
uuid = "12345678-1234-5678-1234-56789abcdef0"

[[gatt_services.characteristics]]
uuid = "12345678-1234-5678-1234-56789abcdef1"
properties = ["read", "write", "notify"]
read = "open"
write = "encrypted"
value = "00"
```

Access is `never`, `open`, `encrypted`, `authenticated` or
`secure_connections`; a client without the required security is told to
pair. When a client writes, a `gatt_write` event follows. To change a
value and notify subscribers:

```sh
mosquitto_pub -t bluetooth/bridge/request/server/set -m '{"attribute": 18, "value": "2a", "notify": true}'
```

Advertise so centrals can find and connect to it:

```toml
[[advertising]]
data = "0201060908627269646765"
params = { connectable = true, interval_min_ms = 200, interval_max_ms = 300 }
```

## Advertising and periodic advertising

`advertise/start` starts a set at run time with its parameters, data and
scan response (hex AD structures); `advertise/data` changes its data and
`advertise/stop` ends it. On a Bluetooth 5 controller, sets can be extended
(up to the controller's maximum data length, 1650 octets on most) and carry
periodic advertising trains (`periodic/start`). As an observer,
`periodic/sync` follows another device's train; its reports arrive as
`periodic_report` events.

> Needs real hardware for the radio side: these procedures are tested
> against Bumble's virtual controller, whose radio model is simplified.
