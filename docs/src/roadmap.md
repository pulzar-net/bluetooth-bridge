# Roadmap: the milestones after LE

Milestone 1 is Bluetooth LE, released as 0.1.0 (see the
[README](https://github.com/pulzar-net/bluetooth-bridge#readme)). Milestone 2,
Bluetooth Mesh, is in progress on `main`. These are designed
now so that nothing in milestone 1 has to be undone to reach them. LE Audio
(isochronous channels, LC3) is out of scope until someone needs it.

## What milestone 1 already gives them

- `bt-hci` already encodes and decodes the commands and events all of these
  need: BR/EDR link control and its events, CTE and IQ reports, channel
  sounding (LE CS commands and subevent results), periodic advertising with
  responses.
- The event loop dispatches by event; each milestone adds handlers, not a
  new loop.
- L2CAP is keyed by channel identifier with fixed and dynamic channels and
  credit-based flow control; BR/EDR adds the ACL-U signaling channel (CID 1)
  and its modes beside it.
- The key store keeps bonds by identity; it grows a BR/EDR link key field
  and Mesh keeps its own store beside it.
- `bluetooth-numbers` already generates the Mesh opcodes and model ids from
  the SIG's repository; each milestone adds tables where the SIG publishes
  them (the Mesh Protocol's own numbers are not in the SIG's repository, so
  they are constants from the specification).

## Milestone 2: Bluetooth Mesh

**Status (in progress on `main`).** Built: the advertising bearer; the GATT
proxy bearer as client (`ProxyBearer`) and server (`ProxyServer`, one client,
accept and reject filters); network PDU encryption and obfuscation, the
message cache, and sequence numbers persisted with headroom; segmentation
and reassembly with block acknowledgments; the provisioner and the device
side over PB-ADV with every authentication method; the Configuration Server
subset a provisioner needs (Composition Data, AppKey Add, Model App Bind);
the client messages (subscription add, publication set, OnOff, Level); the
Generic OnOff Server; and, in the bridge, provisioning, configuration and
OnOff over MQTT (`[mesh] enabled`). Tested against the specification's
sample data and end to end on Bumble. Not built yet: PB-GATT, the IV update
procedure, the specification's SAR timers, relay, friendship, Health, the
other Generic models and the Sensor client, and Node Identity advertising.

The plan:

A crate `bluetooth-mesh` on the host:

- **Bearers**: the advertising bearer (Mesh Message, Mesh Beacon and PB-ADV
  AD types, sent through an advertising set and heard through the scanner
  with duplicate filtering off for those types) and the GATT bearer (Mesh
  Proxy and Provisioning services over the GATT client and server).
- **Network and transport layers**: network PDU obfuscation and encryption
  (AES-CCM, k1 to k4, s1), the network message cache, IV index and IV update,
  sequence numbers persisted with headroom, segmentation and reassembly with
  the SAR timers, friendship as a Low Power node's friend.
- **Provisioning**: provisioner (PB-ADV and PB-GATT, OOB methods, ECDH from
  the SMP toolbox), and the device side so the bridge can be provisioned
  into an existing network.
- **Access layer and models**: Configuration Server and Client, Health
  Server and Client, the Generic models (OnOff, Level, Default Transition
  Time, Power OnOff, Battery, Location, Property) and Sensor client, with
  opcodes and model ids from the assigned numbers.
- **Bridge**: a mesh network is a set of devices in the same topic scheme;
  provisioning and configuration are requests.
- **Tests**: Bumble does not implement Mesh; the network layer gets the Mesh
  Protocol specification's sample data as test vectors, and end-to-end runs
  use two of our own hosts on Bumble's link plus the nRF52840 running
  Zephyr's mesh samples on the bench.

## Milestone 3: Classic BR/EDR

- **GAP**: inquiry (with RSSI and extended inquiry response, parsed with the
  same AD parser), remote name, page and accept, class of device names from
  the assigned numbers, discoverable and connectable modes.
- **Security**: Secure Simple Pairing (the HCI events drive it: IO
  capability, user confirmation, passkey, OOB), link keys in the bond store,
  Secure Connections on BR/EDR, and cross-transport key derivation (h6, h7
  are already in the crypto module) so one pairing bonds both transports.
- **L2CAP on ACL-U**: the signaling channel, configuration, basic and
  enhanced retransmission modes.
- **SDP**: client (service search, attribute search) and server records.
- **RFCOMM** with serial port (SPP) channels, exposed to the bridge as byte
  streams.
- **Tests**: Bumble implements BR/EDR in its controller and host (SDP,
  RFCOMM), so the same peer-script approach applies.

## Milestone 4: direction finding

- **Connectionless AoA and AoD**: CTE transmit on periodic advertising
  (`LE Set Connectionless CTE Transmit Parameters/Enable`), IQ sampling on a
  synchronized train with an antenna switching pattern, and IQ reports
  (`LE Connectionless IQ Report`) published raw.
- **Connection-oriented CTE** request and response.
- **Angles**: an estimator (MUSIC or a phase-difference method) over the IQ
  samples for a configured antenna array, published per device. Turning
  angles from several receivers into a position is left to the software
  above the bridge.
- **Hardware**: needs a controller with antenna switching (nRF52833 or
  nRF5340 with an antenna board); the capability discovery already reports
  the AoA, AoD and CTE feature bits.

## Milestone 5: channel sounding (Bluetooth 6.0)

- The CS procedure on a connection: capability exchange, security enable,
  configuration, procedure parameters and enable, and the subevent results
  (`LE CS Subevent Result` and `Continue`), reassembled per procedure.
- Distance from round-trip timing and phase-based ranging, published per
  peer, with the raw step data available.
- Only where the controller sets the Channel Sounding feature bit; no
  controller on the bench has it yet (nRF54L15 does).
