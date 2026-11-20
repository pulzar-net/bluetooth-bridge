# Architecture

## Who does what

A Bluetooth system is split at HCI, the Host Controller Interface:

- The **controller** (the chip) runs the radio and the link layer:
  advertising and scanning on the air, connection events, encryption of
  link-layer packets with keys the host gives it.
- The **host** runs everything above: what to scan for and how to report it,
  L2CAP, ATT and GATT, the Security Manager (pairing and keys), privacy, and
  every decision.

On Linux the host is normally the kernel's Bluetooth stack plus BlueZ.
bluetooth-bridge is a complete host of its own: it takes the controller
through the HCI user channel (or speaks H4 on a serial port or TCP), and
nothing else sits between it and the chip. Its behavior therefore depends
on the controller alone, not on the kernel or BlueZ version.

## Layers

```text
 MQTT clients (Home Assistant, Node-RED, scripts)
        │
 bluetooth-bridge ── config, topics, requests, readings, discovery
        │  HostEvent (broadcast)           ▲ Host and Connection methods (async)
        ▼                                  │
 bluetooth-host ──── scanner, advertiser, central and peripheral,
        │            L2CAP, ATT/GATT client and server, SMP, privacy, bonds
        ├── bluetooth-adv      advertising data, beacons and sensors
        ├── bluetooth-numbers  the SIG's assigned numbers
        ├── bt-hci             HCI commands and events (Embassy)
        ▼
 transport ───────── HCI user channel │ H4 serial │ H4 TCP
        │
 the controller (or Bumble's virtual controller)
```

- **The event loop** reads HCI events and ACL data from the transport and
  dispatches them: advertising reports to the scanner, connection events to
  connections, L2CAP to channels, ATT to the GATT client or server, SMP to
  pairing.
- **`Host`** is the handle to all of it. Its methods are async; it can be
  cloned and shared. Events go out on a broadcast channel, so several
  consumers can listen.
- **The bridge** owns the MQTT session. It maps advertisements to `scan/`
  and `device/` topics and MQTT requests to `Host` calls, which run as their
  own tasks so a slow GATT read never stalls scanning.

## The life of an advertisement

1. A BTHome sensor broadcasts. The controller hears it and sends an LE
   Advertising Report (or Extended Advertising Report) event over HCI.
2. bt-hci decodes the event. The scanner reassembles fragmented extended
   reports, merges a scan response, resolves a private address with known
   IRKs, and applies duplicate filtering.
3. bluetooth-adv parses the AD structures and decodes the BTHome service
   data into readings.
4. The bridge publishes the report on `bluetooth/scan/<ADDRESS>`, the
   readings on `bluetooth/device/<ADDRESS>`, and, the first time, Home
   Assistant discovery for each reading.

## Design rules

- **Never panic on input.** Everything parsed from the air or the
  controller is bounds checked and fuzzed.
- **Check before asking.** Every feature checks the controller's
  capabilities first, so old controllers lose features, not stability.
- **Bounded resources.** CI checks that the bridge stays under 8 MB
  resident while scanning a site with 5,000 advertisers.
- **No `unsafe` code**, forbidden by the workspace lints.
- **Small and static.** The static bridge binary must stay under 3 MB.
- **Adopt, don't rewrite.** HCI types, cryptography and the Ruuvi format
  come from maintained crates; the assigned numbers from the SIG's data.
