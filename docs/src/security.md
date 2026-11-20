# Security model

This page describes what bluetooth-bridge protects, what it relies on you
for, and what it cannot do. To report a vulnerability, see
[SECURITY.md](https://github.com/pulzar-net/bluetooth-bridge/blob/main/SECURITY.md):
privately, never in a public issue.

## What is at stake

- **Bonds**: the long term keys and IRKs of paired devices, and the bridge's
  own IRK, in the data directory. With them, someone can impersonate the
  bridge to bonded devices and track devices with private addresses.
- **Keys you configure**: BTHome bind keys, KKM passwords and IRKs in the
  configuration file.
- **Control**: whoever can publish to `bluetooth/bridge/request/#` can
  connect to devices, write their characteristics, pair, and change what the
  bridge serves and advertises.

## Threats and defenses

| Threat | Defense |
|---|---|
| Malformed or hostile packets from a nearby radio | Every parser is bounds checked and fuzzed; no `unsafe` code. Bad packets are dropped. |
| Hostile GATT clients and servers | ATT lengths and offsets are checked; long writes are bounded by each characteristic's `max_len`; per-attribute access levels require encryption or authentication before a value is read or written. |
| Weak pairing | LE Secure Connections is supported in every association model; `secure_connections_only` refuses legacy pairing and `mitm` refuses Just Works. Debug keys and reflected public keys are rejected. |
| Keys leaking through MQTT | Keys are never published; `bonds` reports only who is bonded and how. |
| Keys leaking through files | Bonds and the local identity are written atomically with mode 0600. |
| Tracking through the bridge's own address | The bridge can use a static random address, and resolves private addresses only with keys it holds. |

## What you are responsible for

- **The MQTT broker.** The bridge does whatever authorized MQTT clients ask.
  Require authentication on the broker, use its access control so only the
  bridge and trusted clients can publish to `bluetooth/#`, and keep it off
  untrusted networks.
- **The configuration and data directory.** They hold keys; keep them
  readable by the bridge's user only, and protect backups.
- **Passkeys in the log.** A passkey the bridge shows during pairing is
  logged at `info`, so whoever reads the log can complete that pairing.
- **Privacy of the people around.** The bridge publishes every device it
  hears, phones and watches included, unless `scan.allow` narrows it. Narrow
  it, and keep `scan/` topics off brokers others can read.

## Current limits

- **No TLS to the MQTT broker yet.** Run the broker on the same host or a
  trusted network, or put a TLS tunnel in between.
- **Not qualified** by the Bluetooth SIG, and not yet through a third-party
  security audit.
