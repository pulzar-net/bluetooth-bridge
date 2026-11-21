# bluetooth-host

[![crates.io](https://img.shields.io/crates/v/bluetooth-host.svg)](https://crates.io/crates/bluetooth-host)
[![docs.rs](https://img.shields.io/docsrs/bluetooth-host)](https://docs.rs/bluetooth-host)

A Bluetooth host stack over raw HCI.

```sh
cargo add bluetooth-host
```

It talks to a controller directly, over the Linux HCI user channel, H4 on
a serial port, or H4 over TCP, so the same features work on every board
with no BlueZ or D-Bus. HCI commands and events are encoded and decoded by
the `bt_hci` crate; everything above HCI is here:

- controller capability discovery, so features degrade cleanly on old chips;
- the observer: passive and active scanning, legacy and extended reports,
  the coded PHY, periodic advertising sync, duplicate filtering, and
  private addresses resolved to identities;
- the broadcaster: legacy, extended and periodic advertising sets;
- central and peripheral connections, parameter, PHY and data length updates;
- L2CAP signaling and LE credit-based channels;
- ATT, a GATT client, and a GATT server built at run time;
- SMP: legacy and Secure Connections pairing, every association model,
  bonding with a persistent key store, and privacy.

<!-- ANCHOR: scan -->
```rust,no_run
# async fn demo() -> bluetooth_host::Result<()> {
use bluetooth_host::{Host, HostConfig, HostEvent, ScanConfig};
let host = Host::open(&"hci0".parse().unwrap(), HostConfig::default()).await?;
let mut events = host.events();
host.start_scan(ScanConfig::default()).await?;
while let Ok(HostEvent::Advertisement(r)) = events.recv().await {
    println!("{} {} dBm {:?}", r.device(), r.rssi, r.advertisement().local_name);
}
# Ok(()) }
```
<!-- ANCHOR_END: scan -->

Part of [bluetooth-bridge](https://github.com/pulzar-net/bluetooth-bridge), maintained by
[Pulzar](https://pulzr.net). See the [user guide](https://oss.pulzr.net/bluetooth-bridge/), the
[library guide](https://oss.pulzr.net/bluetooth-bridge/library/index.html) and the
[API documentation](https://oss.pulzr.net/bluetooth-bridge/api/bluetooth_host/index.html).

License: MIT.
