# bluetooth-mesh-stack

[![crates.io](https://img.shields.io/crates/v/bluetooth-mesh-stack.svg)](https://crates.io/crates/bluetooth-mesh-stack)
[![docs.rs](https://img.shields.io/docsrs/bluetooth-mesh-stack)](https://docs.rs/bluetooth-mesh-stack)

Bluetooth Mesh on the bluetooth-host stack (work in progress).

```sh
cargo add bluetooth-mesh-stack
```

What is here so far: the security toolbox (s1, k1 to k4), network PDU
encryption and obfuscation, lower and upper transport with segmentation and
reassembly, provisioning on both sides over PB-ADV, the access layer with
Composition Data, the Configuration models a provisioner needs, Generic
OnOff and Level, and a runtime that provisions, configures and controls
nodes, or runs as a node, over the advertising bearer or the GATT proxy.
The API will change before it is released.

Part of [bluetooth-bridge](https://github.com/pulzar-net/bluetooth-bridge), maintained by
[Pulzar](https://pulzr.net). See the [user guide](https://pulzar-net.github.io/bluetooth-bridge/), the
[library guide](https://pulzar-net.github.io/bluetooth-bridge/library/index.html) and the
[API documentation](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_mesh_stack/index.html).

License: MIT.
