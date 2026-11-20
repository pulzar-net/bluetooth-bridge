---
title: "Troubleshooting and FAQ"
description: "Start with the log."
---

Start with the log. Run the bridge with `RUST_LOG=debug` for every
request and event, or `RUST_LOG=bluetooth_host=debug,info` for the host
stack alone.

## The bridge does not start

**`hci0 stays busy: is bluetoothd running, or the interface up?`** The
user channel needs the controller to itself. Stop BlueZ
(`sudo systemctl disable --now bluetooth`). If it is still busy, the
interface is up: `sudo btmgmt --index 0 power off`, or reboot with BlueZ
disabled. While the kernel is still loading the chip's firmware, the bridge
waits and retries on its own.

**`Operation not permitted` opening `hci0`.** The user channel needs
`CAP_NET_ADMIN`: run as root, or use the [systemd unit](/bluetooth-bridge/installation.html#as-a-systemd-service).

**No `hci0`.** The kernel has no driver for the controller, or its firmware
is missing: check `dmesg` for the btusb (or UART) driver's messages and
install the firmware package. A UART controller without a driver uses
`serial:`.

**A `serial:` controller does not answer.** Check the baud rate and flow
control (`:noflow` turns RTS/CTS off) against the controller's firmware.

## Sensors

**A sensor does not appear on `bluetooth/device/`.** Look for it on
`bluetooth/scan/#`:

- It is there with `"beacons": []`: the bridge does not decode its format
  yet. [Tell us](https://github.com/pulzar-net/bluetooth-bridge/issues/new?template=device.yml),
  with a few of its `scan/` messages.
- It is there with `"undecryptable": true`: it encrypts; add its key
  ([Sensors and beacons](/bluetooth-bridge/sensors.html)).
- It is not there: check `scan.allow` and `scan.min_rssi`, and range. A
  sensor that only advertises on the coded PHY needs a controller that
  supports it.

**A device keeps changing address.** It uses private addresses. Pair with it
or enter its IRK; see [Devices with private addresses](/bluetooth-bridge/sensors.html#devices-with-private-addresses).

**Too much MQTT traffic.** Use `scan.dedup = "changes"` or a longer
interval, `scan.allow` for the devices you care about, and
`scan.publish_reports = false`.

## Connections

**`connect` times out.** The device must be advertising as connectable
(`"connectable": true` on its `scan/` topic) and in range. Many devices stop
advertising while connected to something else, such as a phone.

**Pairing fails.** Compare the device's needs with `[adapter]`: a device
that requires MITM protection cannot pair with `no_input_no_output`; set an
`io_capability` and a `passkey` that it accepts. `pairing_failed` events
carry the reason.

## FAQ

**Can BlueZ and bluetooth-bridge share one controller?** No. The HCI user
channel gives one program exclusive access. Use a second controller (a USB
dongle) for the bridge if the machine needs BlueZ too.

**Does it support Bluetooth Classic (audio, keyboards, serial ports)?** Not
yet; Classic BR/EDR is on the [roadmap](/bluetooth-bridge/roadmap.html).

**Does it work on macOS or Windows?** The HCI user channel is Linux only.
`serial:` and `tcp:` transports work wherever the bridge builds, but there
are no release binaries for other systems.

**Where do I ask a question?** In
[Discussions](https://github.com/pulzar-net/bluetooth-bridge/discussions).
Bugs go in [issues](https://github.com/pulzar-net/bluetooth-bridge/issues). For security
problems, see [SECURITY.md](https://github.com/pulzar-net/bluetooth-bridge/blob/main/SECURITY.md).
