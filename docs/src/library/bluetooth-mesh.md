# bluetooth-mesh

Bluetooth Mesh on the bluetooth-host stack. **Work in progress** on `main`,
not in a release; the API will change. [API docs](https://pulzar-net.github.io/bluetooth-bridge/api/bluetooth_mesh/index.html).

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

It is tested end to end on two Bumble controllers. The bridge does not
expose Mesh on MQTT yet; see the [roadmap](../roadmap.md).
