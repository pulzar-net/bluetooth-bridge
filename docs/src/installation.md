# Installation

bluetooth-bridge is one static Linux binary. Pick one of the ways below,
then [configure](configuration.md) it.

## Release binaries

Each [release](https://github.com/pulzar-net/bluetooth-bridge/releases) has
statically linked binaries with no runtime dependencies, and a `SHA256SUMS`
file:

| File | For |
|---|---|
| `bluetooth-bridge-x86_64-linux-musl` | PCs and servers |
| `bluetooth-bridge-aarch64-linux-musl` | Raspberry Pi 3, 4, 5 and other 64-bit ARM boards with a 64-bit OS |
| `bluetooth-bridge-mipsel-linux-musl` | MT7621 and MT7628 routers (little-endian MIPS) |

Download, verify and install (this is the README's quick start; CI runs it):

```sh
VERSION=0.1.0
ARCH=$(uname -m)   # x86_64 or aarch64
BASE=https://github.com/pulzar-net/bluetooth-bridge/releases/download/v$VERSION
curl -fsSLO "$BASE/bluetooth-bridge-$ARCH-linux-musl"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
sudo install -m 0755 "bluetooth-bridge-$ARCH-linux-musl" /usr/local/bin/bluetooth-bridge
bluetooth-bridge --version
```

Big-endian targets are not supported: the HCI types crate the stack uses
assumes little-endian.

## From source

With Rust 1.89 or newer. The Bluetooth SIG's assigned numbers are a git
submodule that the build reads, so clone with submodules:

```sh
git clone --recurse-submodules https://github.com/pulzar-net/bluetooth-bridge
cd bluetooth-bridge
cargo build --release -p bluetooth-bridge
```

or `cargo install --locked --git https://github.com/pulzar-net/bluetooth-bridge bluetooth-bridge`
(cargo fetches submodules of git dependencies itself).

## Taking the controller from BlueZ

With the HCI user channel (`transport = "hci0"`), the bridge has the
controller to itself; the kernel's driver still loads the chip's firmware.
BlueZ must not use it at the same time:

```sh
sudo systemctl disable --now bluetooth
```

The user channel needs `CAP_NET_ADMIN`. The systemd unit below gives the
bridge that one capability, not root.

A UART controller with no kernel driver (an nRF52840 running Zephyr's
`hci_uart`, say) needs neither: use `transport = "serial:/dev/ttyACM0:1000000"`.

## As a systemd service

The repository has a hardened unit in
[`contrib/systemd/bluetooth-bridge.service`](https://github.com/pulzar-net/bluetooth-bridge/blob/main/contrib/systemd/bluetooth-bridge.service).
It runs the bridge as an unprivileged dynamic user with only
`CAP_NET_ADMIN`, keeps its bonds in `/var/lib/bluetooth-bridge`, and
restarts it on failure.

```sh
sudo mkdir -p /etc/bluetooth-bridge
sudo cp config.example.toml /etc/bluetooth-bridge/config.toml   # then edit it
sudo install -m 0644 contrib/systemd/bluetooth-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bluetooth-bridge
journalctl -u bluetooth-bridge -f
```

For a serial controller, the `dialout` group in the unit gives access to the
port.

## On OpenWrt

> Needs real hardware: this procedure has not been tested on a router yet.

The `mipsel` binary runs on MT7621 and MT7628 routers with OpenWrt.

1. Install the kernel side: `kmod-bluetooth`, and `kmod-btusb` plus the
   firmware package for a USB dongle (for example
   `rtl8761bu-firmware`). Do not install or start `bluez-daemon`.
2. Copy the binary to `/usr/bin/bluetooth-bridge` and make it executable.
3. Write `/etc/bluetooth-bridge/config.toml`. **Set `[data] dir` to a
   directory on flash**, such as `/etc/bluetooth-bridge/data`: `/var` is in
   RAM on OpenWrt, and bonds would be lost at reboot.
4. Install the procd script from
   [`contrib/openwrt/bluetooth-bridge.init`](https://github.com/pulzar-net/bluetooth-bridge/blob/main/contrib/openwrt/bluetooth-bridge.init):

```sh
cp bluetooth-bridge.init /etc/init.d/bluetooth-bridge
chmod +x /etc/init.d/bluetooth-bridge
/etc/init.d/bluetooth-bridge enable
/etc/init.d/bluetooth-bridge start
logread -f -e bluetooth-bridge
```

## Command line

```text
bluetooth-bridge [--config FILE]   run the bridge (default /etc/bluetooth-bridge/config.toml)
bluetooth-bridge probe TRANSPORT   name the controller at TRANSPORT (hci0, serial:PATH:BAUD,
                                   tcp:HOST:PORT) as JSON, and exit
bluetooth-bridge --version
```

Exit status: 0 on a clean stop, 1 on an error, 2 for bad arguments.

The log goes to standard error. `RUST_LOG` sets its level per target, for
example `RUST_LOG=debug` or `RUST_LOG=bluetooth_host=debug,info`.
