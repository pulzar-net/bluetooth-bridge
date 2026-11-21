---
title: "bluetooth-numbers"
description: "The Bluetooth SIG's Assigned Numbers as lookup functions: company identifiers; service, characteristic, descriptor, unit, member and SDO UUIDs; AD types; appearances; URI schemes; core versions;..."
---

The Bluetooth SIG's Assigned Numbers as lookup functions: company
identifiers; service, characteristic, descriptor, unit, member and SDO
UUIDs; AD types; appearances; URI schemes; core versions; PSMs; format
types; and the Mesh opcodes and model identifiers. [crates.io](https://crates.io/crates/bluetooth-numbers), [docs.rs](https://docs.rs/bluetooth-numbers), [API docs for `main`](https://oss.pulzr.net/bluetooth-bridge/api/bluetooth_numbers/index.html).

```rust
assert_eq!(bluetooth_numbers::company(0x004c), Some("Apple, Inc."));
```

The tables are generated at build time from the YAML in the SIG's
[public repository](https://bitbucket.org/bluetooth-SIG/public), checked out
as a git submodule (`crates/bluetooth-numbers/sig`). Nothing is typed in by
hand: a new assignment arrives with an update of the submodule. The data
remains the SIG's; it is not copied into this repository.
