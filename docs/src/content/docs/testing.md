---
title: "Testing"
description: "The whole stack is developed and tested without hardware."
---

The whole stack is developed and tested without hardware. CI runs every
test on every commit.

## Running the tests

The end-to-end tests need Bumble, in a Python virtual environment:

```sh
python3 -m venv .venv && .venv/bin/pip install -r tests/bumble/requirements.txt
BUMBLE_PYTHON=.venv/bin/python cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Without `BUMBLE_PYTHON` those tests are skipped (CI sets `BUMBLE_REQUIRED`,
which turns a skip into a failure). Everything else runs with
`cargo test --workspace` alone.

## End to end, against Bumble

[Bumble](https://github.com/google/bumble) provides virtual controllers on a
simulated radio link. The host under test reaches one over H4 on TCP,
exactly as it would a real controller, and `tests/bumble/peer.py` scripts a
Bumble device on the same link as the other side:

- `crates/bluetooth-host/tests/bumble.rs`: scanning, advertising, periodic
  sync, central and peripheral GATT, L2CAP channels both ways, every pairing
  method in both roles with bonding and re-encryption, private address
  resolution;
- `crates/bluetooth-bridge/tests/mqtt.rs`: the bridge with an MQTT broker:
  advertisements, readings, Home Assistant discovery, and requests;
- `crates/bluetooth-mesh-stack/tests/bumble.rs`: provisioning, configuration and
  control of mesh nodes over the advertising bearer and through a proxy, on
  two controllers;
- `ci/quickstart.sh`: the README's quick start as written, with the release
  binary and the current build.

## HCI replay

`crates/bluetooth-host/tests/replay.rs` runs the host against a scripted
controller that answers commands with exact event bytes. It covers what
Bumble's simplified radio model cannot (advertising set ids, legacy bits,
fragmented reports, scan responses) and the limits of a Bluetooth 4
controller. Recorded traffic from real chips goes here.

## Test vectors

The cryptography (AES-CMAC, the SMP functions, Mesh's s1 and k1 to k4, and
network PDU encryption) is checked against the sample data in the Core
Specification (Vol 3, Part H, Appendix D) and the Mesh Protocol
specification.

## Fuzzing

Every parser that reads the air or the controller has a
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target in `fuzz/`,
fuzzed in CI on every commit, and a stable smoke pass over the same targets
runs with `cargo test -p bluetooth-host --features fuzzing --test fuzz_smoke`. Locally (needs a nightly
toolchain):

```sh
cargo install cargo-fuzz
cd fuzz && cargo +nightly fuzz list
```

## Budgets

- **Memory:** under 8 MB resident scanning a busy site (5,000 advertisers,
  200,000 reports).
- **Binary size:** under 3 MB for the static bridge, built for `aarch64`
  and `mipsel` in CI, with tests run under qemu.

## Documentation

The `docs` workflow checks the claims this site makes: the
[configuration reference](/bluetooth-bridge/config-reference.html) is regenerated from the code
and compared, every doctest runs (the README's library example among them),
the README's quick start runs against Bumble, the workspace builds on the
minimum supported Rust version, and every relative link resolves.

## Real hardware

> Not done yet. Bench testing on real controllers is the next step.
