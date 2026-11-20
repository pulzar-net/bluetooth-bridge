# Configuration

bluetooth-bridge reads one TOML file, `/etc/bluetooth-bridge/config.toml`
unless `--config FILE` names another. Only the transport is required:

```toml
[adapter]
transport = "hci0"
```

Everything else has a default. Unknown keys and wrong types are errors
(except in `[scan]`, see the reference), so a typo stops the bridge at
startup. The [configuration reference](config-reference.md) lists every
key; it is generated from the code, so it is always current.

A [JSON Schema](config.schema.json) generated from the same code lets an
editor with TOML schema support (Taplo, or VS Code's Even Better TOML)
complete and check the file. Point it at the schema with a first line of:

```toml
#:schema https://pulzar-net.github.io/bluetooth-bridge/config.schema.json
```

## The tables

| Table | What it sets |
|---|---|
| `[adapter]` | the transport, the GAP name and appearance, pairing (IO capability, passkey, bonding, MITM, Secure Connections only), and whether to use a random address |
| `[mqtt]` | broker host and port, user name, password file, client id, base topic, keep-alive |
| `[scan]` | whether to scan, active or passive, interval and window, coded PHY, filter accept list, duplicate filtering, an address allow list, a minimum RSSI, whether to publish every report |
| `[homeassistant]` | discovery on or off, the discovery prefix, Home Assistant's status topic |
| `[data]` | the data directory |
| `[[bthome_keys]]` | bind keys of encrypted BTHome devices |
| `[[kkm_passwords]]` | passwords of KKM beacons with encrypted frames |
| `[[irks]]` | IRKs of devices known without pairing, so their private addresses resolve |
| `[[gatt_services]]` | GATT services the bridge serves to centrals |
| `[[advertising]]` | advertising sets started with the bridge |

## Transports

| `transport` | For |
|---|---|
| `hci0` (or `hci1`, ...) | a controller with a Linux kernel driver: built-in chips, USB dongles. Uses the HCI user channel. |
| `serial:/dev/ttyACM0:1000000` | a UART controller with no kernel driver, H4 at that baud rate with RTS/CTS; append `:noflow` for none |
| `tcp:127.0.0.1:9000` | H4 over TCP: Bumble's virtual controller, or a network HCI bridge |

## A complete example

[`config.example.toml`](https://github.com/pulzar-net/bluetooth-bridge/blob/main/config.example.toml)
in the repository sets every key to its default, with comments, and shows
each list table commented out. CI checks that it parses.

```toml
{{#include ../../config.example.toml}}
```

## Duplicate filtering and traffic

A busy site has thousands of advertisers, each repeating several times a
second. `scan.dedup` decides how much of that reaches MQTT:

| `dedup` | Publishes a device |
|---|---|
| `"off"` | on every advertisement received |
| `"changes"` | when its data changes |
| `{ interval_ms = 10000 }` (default) | when its data changes, and at least every 10 s while it is heard |

`scan.allow` (address prefixes such as `"BC:57:29"`) and `scan.min_rssi`
narrow it further, and `scan.publish_reports = false` stops the per-report
`scan/` topic while keeping decoded `device/` readings.

## The data directory

`[data] dir` (default `/var/lib/bluetooth-bridge`) holds the bonds (long
term keys and IRKs of paired devices) and the bridge's own identity (its IRK
and static random address), written atomically with mode 0600. Back it up;
without it, bonded devices must pair again.

## Logging

The bridge logs to standard error at `info` unless `RUST_LOG` says
otherwise. `RUST_LOG` takes a default level and per-target levels, such as
`debug` or `bluetooth_host=debug,info`. During pairing, a passkey the
bridge shows is logged at `info`, so the person pairing can read it there.
