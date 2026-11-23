---
title: "MQTT API"
description: "The bridge publishes and listens under one base topic, bluetooth unless mqtt.base_topic says otherwise."
---

The bridge publishes and listens under one base topic, `bluetooth` unless
`mqtt.base_topic` says otherwise. Every payload is JSON. This page uses the
default base topic throughout.

This page explains how the topics work together. The
[MQTT reference](/bluetooth-bridge/mqtt-reference.html) lists every topic with its QoS, retain flag and
payload schema, field by field. It is generated from the bridge's own types,
so it always matches the code.

Bridge topics are `bluetooth/bridge/state`, `info` and `event`, with
requests and responses under `bluetooth/bridge/request/<op>` and
`bluetooth/bridge/response/<op>`. Each device has `bluetooth/scan/<ADDRESS>`
for its advertisements and, when they carry readings,
`bluetooth/device/<ADDRESS>`. The mesh has `bluetooth/mesh/event`.

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

Every field is described in the [MQTT reference](/bluetooth-bridge/mqtt-reference.html). Features the controller lacks are simply not used: scanning without coded
PHY, legacy advertising without extended sets, and so on.

## `scan/<ADDRESS>`

Every advertisement that passes [duplicate filtering](/bluetooth-bridge/configuration.html#duplicate-filtering-and-traffic),
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
data in hex. Turn the topic off with `scan.publish_reports = false`. The
[MQTT reference](/bluetooth-bridge/mqtt-reference.html) has every field, and each beacon format's.

## `device/<ADDRESS>`

The readings decoded from a sensor's beacons, merged, with its signal
strength and when it was last heard (Unix milliseconds):

```json
{ "temperature": 25.06, "humidity": 50.55, "rssi": -50, "last_seen": 1795138399393 }
```

Only devices with decoded readings get this topic, and a Home Assistant
device. See [Sensors and beacons](/bluetooth-bridge/sensors.html) for the formats.

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

An empty payload is the same as `{}`. A request of the wrong shape, such as
a string where a number belongs, gets an error response that names the
problem. Each request's fields and its response are in the
[MQTT reference](/bluetooth-bridge/mqtt-reference.html); what follows says what each group does.

### Scanning

`scan/start` starts scanning, or restarts it with another `config`: the
[`[scan]` keys](/bluetooth-bridge/config-reference.html) other than `enabled`, `allow`, `min_rssi`
and `publish_reports`. `scan/stop` stops it.

### Connections

`connect` connects to an `address` as central, with optional connection
`params`, and answers with the connection's `handle`, which every request
on it names. `disconnect` closes it, and `connections` lists the open ones.
`connection/params`, `connection/phy` (`le1m`, `le2m`, `le_coded`) and
`connection/data_length` change a connection, and `connection/rssi` reads
its signal strength.

### GATT client

`gatt/mtu` exchanges the ATT MTU, and `gatt/discover` lists a peer's
services, characteristics and descriptors with their handles. `gatt/read`
and `gatt/write` take an `attribute` handle and hex values; `gatt/subscribe`
takes a characteristic's value handle, and its notifications and
indications then arrive as `notification` events.

### Security

`pair` pairs with a peer, and `secure` encrypts the link with the stored
bond, pairing when there is none; both answer with the security reached.
`bonds` lists the stored bonds, never their keys, and `unpair` forgets one.

### Advertising

`advertise/start` starts a set with `params` as in
[`[[advertising]]`](/bluetooth-bridge/config-reference.html) and hex AD structures, and answers with
the set's handle; `advertise/data` and `advertise/stop` change and stop it.
`periodic/start` and `periodic/stop` run a periodic train on an extended
set. `periodic/sync` follows another device's train, whose reports then
arrive as `periodic_report` events, until `periodic/terminate`.

### GATT server

`server/add` adds a service, defined as in
[`[[gatt_services]]`](/bluetooth-bridge/config-reference.html), and answers with its handles.
`server/set` sets a value, notifying subscribed clients with `notify`, and
`server/get` reads one.

### Other

`info` answers with the controller, as in `bridge/info`.

## Events

On `bluetooth/bridge/event`, `type` names the event: `connected`,
`disconnected`, `paired`, `pairing_failed`, `notification`, `connection` (a
parameter, PHY or data length change), `gatt_write` and `gatt_subscription`
(a client of the bridge's GATT server), `periodic_report`,
`periodic_sync_lost`, `advertising_stopped` and `scan_request`. The
[MQTT reference](/bluetooth-bridge/mqtt-reference.html) has each event's fields.

```json
{ "type": "notification", "handle": 64, "attribute": 42, "value": "6869", "indication": false }
```

## Bluetooth Mesh

Since 0.2.0. With `[mesh] enabled = true`, the bridge is the provisioner of
a mesh network of its own, kept in `<data dir>/mesh`, over the advertising
bearer. Requests go to `bluetooth/bridge/request/mesh/<op>` and answers come
on `bluetooth/bridge/response/mesh/<op>`:

`mesh/network` shows the network and the nodes the bridge provisioned, and
`mesh/unprovisioned` the device beacons heard, newest first.
`mesh/provision` provisions one by its `uuid`, with its `static_oob` if it
has one; `mesh/configure` gives a node the application key, binds its
models and reads its Composition Data; `mesh/onoff` switches its Generic
OnOff server.

Events come on `bluetooth/mesh/event`: `unprovisioned` for a new device
beacon, and `message` for each access message. Mesh advertisements are not published as `scan/`
reports, and the bridge adds the Mesh AD types to `scan.always_report` so
duplicate filtering never drops them.

## Home Assistant topics

With `homeassistant.enabled` (the default), the bridge also publishes
discovery messages under `homeassistant/` for each sensor with decoded
readings, and for the bridge itself. See [Home Assistant](/bluetooth-bridge/home-assistant.html).
