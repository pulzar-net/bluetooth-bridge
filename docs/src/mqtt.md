# MQTT API

The bridge publishes and listens under one base topic, `bluetooth` unless
`mqtt.base_topic` says otherwise. Every payload is JSON. This page uses the
default base topic throughout.

## Topics at a glance

| Topic | Direction | Retained | What |
|---|---|---|---|
| `bluetooth/bridge/state` | out | yes | `{"state":"online"}` or `{"state":"offline"}` |
| `bluetooth/bridge/info` | out | yes | the controller, its version and features |
| `bluetooth/scan/<ADDRESS>` | out | no | an advertisement, fully parsed |
| `bluetooth/device/<ADDRESS>` | out | no | a sensor's decoded readings |
| `bluetooth/bridge/event` | out | no | connections, pairing, notifications, GATT server writes, periodic reports |
| `bluetooth/bridge/request/<op>` | in | | a request |
| `bluetooth/bridge/response/<op>` | out | no | its answer |

`<ADDRESS>` in a topic is the address as twelve upper-case hex digits, most
significant first: `F12233445566` for `F1:22:33:44:55:66`. When a private
address resolves through a known IRK, it is the identity address, so a
device keeps one topic while its address rotates.

In payloads and requests, addresses are written `F1:22:33:44:55:66/random`
or `F1:22:33:44:55:66/public`; without a suffix an address is public.

Keys are never published.

## `bridge/state` and `bridge/info`

`bridge/state` is `{"state":"online"}` while the bridge runs, and
`{"state":"offline"}` (its last will) when it stops or loses the broker.

`bridge/info` describes the controller:

```json
{
  "address": "D0:11:22:33:44:55",
  "controller": {
    "hci_version": 9, "lmp_version": 9, "manufacturer": 65535,
    "public_address": "D0:11:22:33:44:55",
    "adv_sets": 240, "max_adv_data": 1650,
    "filter_accept_list_size": 8, "resolving_list_size": 8,
    "le_acl": [27, 64], "max_data_length": [27, 10000, 27, 10000], ...
  },
  "core_version": "Bluetooth® Core Specification 5.0",
  "le_features": ["le_encryption", "connection_parameters_request", "extended_reject_indication", "peripheral_initiated_features_exchange", "le_ping", "data_length_extension", "ll_privacy", "extended_scanner_filter_policies", ...]
}
```

Features the controller lacks are simply not used: scanning without coded
PHY, legacy advertising without extended sets, and so on.

## `scan/<ADDRESS>`

Every advertisement that passes [duplicate filtering](configuration.md#duplicate-filtering-and-traffic),
with its scan response when one came (abridged):

```json
{
  "address": "F1:22:33:44:55:66/random",
  "rssi": -50,
  "connectable": true,
  "data": "0201060c09627...",
  "advertisement": {
    "flags": { "le_general_discoverable": true, "br_edr_not_supported": true, ... },
    "local_name": { "complete": true, "name": "bumble-peer" },
    "manufacturer_data": [ { "company_id": 65535, "data": "68656c6c6f" } ],
    "service_data": [ { "uuid": "fcd2", "name": "Allterco Robotics ltd", "data": "4002ca0903bf13" } ]
  },
  "beacons": [
    {
      "format": "bt_home", "encrypted": false, "trigger_based": false, "undecryptable": false,
      "measurements": [
        { "name": "temperature", "object_id": 2, "value": 25.06, "unit": "°C" },
        { "name": "humidity", "object_id": 3, "value": 50.55, "unit": "%" }
      ]
    }
  ]
}
```

Other fields appear when they apply: `identity` (a resolved private
address), `tx_power`, `primary_phy` and `secondary_phy`, `sid` (extended
advertising set), and every other AD type the advertisement carries, named
from the Bluetooth SIG's assigned numbers. `data` is the raw advertising
data in hex. Turn the topic off with `scan.publish_reports = false`.

## `device/<ADDRESS>`

The readings decoded from a sensor's beacons, merged, with its signal
strength and when it was last heard (Unix milliseconds):

```json
{ "temperature": 25.06, "humidity": 50.55, "rssi": -50, "last_seen": 1795138399393 }
```

Only devices with decoded readings get this topic, and a Home Assistant
device. See [Sensors and beacons](sensors.md) for the formats.

## Requests and responses

Publish a request to `bluetooth/bridge/request/<op>`; the answer comes on
`bluetooth/bridge/response/<op>`:

```json
{ "status": "ok", "data": { "handle": 64, "params": { ... } }, "transaction": "1" }
{ "status": "error", "error": "no connection 9", "transaction": "1" }
```

Add a `transaction` value to a request to have it copied into the response.
Requests that wait for the radio (connecting, reading, pairing) run
alongside each other and scanning.

### Scanning

| Op | Fields | Data |
|---|---|---|
| `scan/start` | `config`: the [`[scan]` keys](config-reference.md) other than `enabled`, `allow`, `min_rssi`, `publish_reports` | |
| `scan/stop` | | |

### Connections

| Op | Fields | Data |
|---|---|---|
| `connect` | `address`, `params` (optional: `scan_interval_ms`, `scan_window_ms`, `timeout_ms`, `phys`, and `params` for the connection interval, latency and supervision timeout) | `handle`, `params` |
| `disconnect` | `handle` | |
| `connections` | | each: `handle`, `address`, `identity`, `role`, `params`, `security`, `mtu` |
| `connection/params` | `handle`, `params` | the parameters agreed |
| `connection/phy` | `handle`, `tx`, `rx` (lists of `le1m`, `le2m`, `le_coded`), `coded_s8` | `tx`, `rx` |
| `connection/data_length` | `handle`, `tx_octets`, `tx_time` | |
| `connection/rssi` | `handle` | `rssi` |

### GATT client

| Op | Fields | Data |
|---|---|---|
| `gatt/mtu` | `handle`, `mtu` | `mtu` |
| `gatt/discover` | `handle` | services, characteristics and descriptors with their handles |
| `gatt/read` | `handle`, `attribute` | `value` (hex) |
| `gatt/write` | `handle`, `attribute`, `value` (hex), `without_response` | |
| `gatt/subscribe` | `handle`, `attribute` (the characteristic's value handle), `notify`, `indicate` | |

Notifications and indications arrive as `notification` events.

### Security

| Op | Fields | Data |
|---|---|---|
| `pair` | `handle` | the security reached |
| `secure` | `handle`: encrypt with the stored bond, or pair | the security reached |
| `bonds` | | each: `identity`, `label`, `has_ltk`, `has_irk`, `authenticated`, `secure_connections` (never the keys) |
| `unpair` | `address` | `removed` |

### Advertising

| Op | Fields | Data |
|---|---|---|
| `advertise/start` | `params` (as in [`[[advertising]]`](config-reference.md)), `data`, `scan_response` (hex AD structures) | `set` |
| `advertise/data` | `set`, `data`, `scan_response` | |
| `advertise/stop` | `set` | |
| `periodic/start` | `set`, `params`, `data` | |
| `periodic/stop` | `set` | |
| `periodic/sync` | `address`, `sid`, `skip`, `timeout_ms` (default 5000) | `sync` |
| `periodic/terminate` | `sync` | |

### GATT server

| Op | Fields | Data |
|---|---|---|
| `server/add` | `service`: a service definition, as in [`[[gatt_services]]`](config-reference.md) | the handles of the service, its characteristics and descriptors |
| `server/set` | `attribute`, `value` (hex), `notify` | `notified` (how many clients), when `notify` |
| `server/get` | `attribute` | `value` |

### Other

| Op | Data |
|---|---|
| `info` | `address`, `controller`, `le_features`, as in `bridge/info` |

## Events

On `bluetooth/bridge/event`, each with a `type`:

| `type` | Fields |
|---|---|
| `connected` | `handle`, `address`, and the connection's role and parameters |
| `disconnected` | `handle`, `address`, `reason` |
| `paired` | `handle`, `identity`, `bonded`, `security` |
| `pairing_failed` | `handle`, `reason` |
| `notification` | `handle`, `attribute`, `value` (hex), and whether it was an indication |
| `connection` | `handle`, `change`: a parameter, PHY or data length change |
| `gatt_write` | `handle`, `attribute`, `value`: a client wrote to the bridge's GATT server |
| `gatt_subscription` | `handle`, `attribute`, `notify`, `indicate` |
| `periodic_report` | `report` (with its data parsed), from a synchronized train |
| `periodic_sync_lost` | `sync` |
| `advertising_stopped` | `set`, `connection` (when a central connected) |
| `scan_request` | `set`, `scanner` |

## Home Assistant topics

With `homeassistant.enabled` (the default), the bridge also publishes
discovery messages under `homeassistant/` for each sensor with decoded
readings, and for the bridge itself. See [Home Assistant](home-assistant.md).
