---
title: "bluetooth-mesh-stack"
description: "Bluetooth Mesh on the bluetooth-host stack."
---

Bluetooth Mesh on the bluetooth-host stack. New in 0.2.0, and still growing
(PB-GATT, IV update, relay and friendship come next), so its API will change. [crates.io](https://crates.io/crates/bluetooth-mesh-stack), [docs.rs](https://docs.rs/bluetooth-mesh-stack), [API docs for `main`](https://oss.pulzr.net/bluetooth-bridge/api/bluetooth_mesh_stack/index.html).

What is there:

- the security toolbox (s1, k1 to k4) and network PDU encryption and
  obfuscation, checked against the Mesh Protocol specification's sample data;
- lower and upper transport: segmentation and reassembly, block
  acknowledgments, application and device key encryption;
- provisioning on both sides (ECDH P-256, every authentication method) over
  PB-ADV, and the advertising bearer's beacons;
- the access layer: Composition Data, the Configuration models a provisioner
  needs, Generic OnOff and Level;
- a runtime that provisions, configures and controls nodes, and runs as a
  node, over the advertising bearer or GATT through the Mesh Proxy service.

It is tested end to end on two Bumble controllers. The bridge uses it as a
provisioner (`[mesh] enabled`, see the [MQTT API](/bluetooth-bridge/mqtt.html#bluetooth-mesh));
the [roadmap](/bluetooth-bridge/roadmap.html) lists what is built and what comes next.
