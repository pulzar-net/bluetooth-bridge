# bluetooth-numbers

The Bluetooth SIG's Assigned Numbers, as lookup functions.

Every table is generated at build time from the YAML the SIG publishes in
its public repository (<https://bitbucket.org/bluetooth-SIG/public>), so the
names here are the SIG's own and a new assignment arrives with an update of
that repository, never by editing this crate.

```rust
assert_eq!(bluetooth_numbers::company(0x004c), Some("Apple, Inc."));
assert_eq!(bluetooth_numbers::service(0x180f).map(|s| s.name), Some("Battery"));
```

Part of [bluetooth-bridge](https://github.com/pulzar-net/bluetooth-bridge), maintained by
[Pulzar](https://pulzr.net). See the [user guide](https://pulzar-net.github.io/bluetooth-bridge/), the
[library guide](https://pulzar-net.github.io/bluetooth-bridge/library/index.html) and the
[API documentation](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_numbers/index.html).

License: MIT.
