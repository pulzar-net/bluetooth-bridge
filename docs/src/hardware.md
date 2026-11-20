# Hardware

bluetooth-bridge drives a Bluetooth controller over standard HCI. It asks
the controller what it supports at start and uses only that, so a
Bluetooth 4 chip works with fewer features rather than failing.

> **No release has been tested on real hardware yet.** "Expected" below
> means the controller speaks standard HCI, which the stack implements and
> tests against Bumble's virtual controller and recorded HCI traffic.
> Reports that something works, or does not, are very welcome: open a
> [hardware report](https://github.com/pulzar-net/bluetooth-bridge/issues/new?template=device.yml).

## Controllers

| Controller | Transport | Notes | State |
|---|---|---|---|
| Realtek RTL8761B(U) dongles: TP-Link UB500, ASUS USB-BT500 | `hci0` | Bluetooth 5: extended advertising, 2M and coded PHY, data length extension. The kernel's btusb driver loads `rtl8761bu_fw`. | expected |
| Nordic nRF52840 Dongle (PCA10059) | `serial:/dev/ttyACM0:1000000`, or `hci0` with `hci_usb` | Zephyr's `hci_uart` or `hci_usb` sample: the full Bluetooth 5 feature set | expected |
| Raspberry Pi 3, 4, 5 built-in | `hci0` | Broadcom/Cypress chips: Bluetooth 4.1 (Pi 3) or 5.0 (Pi 4, 5) | expected |
| Intel AX200, AX210 and other btusb controllers | `hci0` | | expected |
| Bluetooth 4.0 dongles (CSR8510 and similar) | `hci0` | no extended advertising, 2M or coded PHY | expected |
| A UART chip that needs vendor setup (firmware upload, baud change) without a kernel driver | `serial:` | the stack does no vendor setup | unsupported |

With `hci0`, the kernel driver loads the chip's firmware and sets it up;
the bridge then takes the controller through the HCI user channel.

## Check a controller

```sh
sudo bluetooth-bridge probe hci0
```

prints the controller's address, HCI and LMP versions, manufacturer,
supported features, buffer sizes, advertising set count and list sizes as
JSON, then exits. `probe` only reads; it does not scan or advertise.

## Flashing an nRF52840 Dongle

> Needs real hardware.

Build Zephyr's
[`hci_uart`](https://docs.zephyrproject.org/latest/samples/bluetooth/hci_uart/README.html)
(or `hci_usb`) sample for `nrf52840dongle/nrf52840` and flash it with
`nrfutil` through the dongle's bootloader (press its reset button to enter
it). With `hci_uart`, the dongle appears as a USB serial port; use
`transport = "serial:/dev/ttyACM0:1000000"`.

## Radio placement

A USB dongle on a short extension cable, away from the computer and USB 3
ports, hears much better than one plugged in directly. Metal enclosures and
walls cut range sharply; the coded PHY (on controllers that support it)
helps with sensors that use it.
