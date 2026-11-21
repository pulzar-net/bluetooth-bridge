# Contributing to bluetooth-bridge

Thanks for helping. Every kind of contribution is welcome: a report that a
controller or sensor works, a bug report with a log, a fix to the docs, a
new sensor format, a new part of the stack.

Please follow the [code of conduct](CODE_OF_CONDUCT.md). Security problems go
through [private reporting](SECURITY.md), never a public issue.

## Before you start

- **Questions** (how do I, is this expected): ask in
  [Discussions](https://github.com/pulzar-net/bluetooth-bridge/discussions).
- **Hardware reports and sensor requests:** use the
  [device or hardware form](https://github.com/pulzar-net/bluetooth-bridge/issues/new?template=device.yml).
  For a sensor, a few of its `bluetooth/scan/<ADDRESS>` messages are what we
  need to add its format.
- **Bugs:** use the [bug form](https://github.com/pulzar-net/bluetooth-bridge/issues/new?template=bug.yml),
  with the version, your configuration and a `RUST_LOG=debug` log.
- **Larger changes** (a new profile, a change to the MQTT API or the
  configuration): open an issue first, so we can agree on the approach
  before you write the code. The [roadmap](https://oss.pulzr.net/bluetooth-bridge/roadmap.html)
  has the design for the next milestones.

## Build

You need Rust 1.89 or newer ([rustup.rs](https://rustup.rs)). The Bluetooth
SIG's assigned numbers are a git submodule that the build reads:

```sh
git clone --recurse-submodules https://github.com/pulzar-net/bluetooth-bridge
cd bluetooth-bridge
cargo build --workspace
```

In an existing clone, `git submodule update --init`.

## Test

The end-to-end tests run against Bumble's virtual controllers, which need
Python:

```sh
python3 -m venv .venv && .venv/bin/pip install -r tests/bumble/requirements.txt
```

Then run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
BUMBLE_PYTHON=.venv/bin/python cargo test --workspace
cargo test -p bluetooth-host --features fuzzing --test fuzz_smoke
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Without `BUMBLE_PYTHON` the Bumble tests are skipped. See
[Testing](https://oss.pulzr.net/bluetooth-bridge/testing.html) for what
each suite covers. To cover something Bumble's radio model cannot, add an
HCI replay case to `crates/bluetooth-host/tests/replay.rs`.

If you change a configuration type, regenerate the configuration reference
and commit the result:

```sh
UPDATE_DOCS=1 cargo test -p bluetooth-bridge --features schema --test config_reference
```

## Try it by hand

```sh
.venv/bin/python tests/bumble/peer.py scan_legacy 9000
cargo run -p bluetooth-bridge -- --config my-test.toml   # [adapter] transport = "tcp:127.0.0.1:9000"
```

[Getting started](https://oss.pulzr.net/bluetooth-bridge/getting-started.html)
walks through it with an MQTT broker.

## Fuzz

Every parser of bytes from the air or the controller has a fuzz target in
`fuzz/`. If you change a parser, fuzz it for a few minutes (needs a nightly
toolchain and `cargo install cargo-fuzz`):

```sh
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run <target> -- -max_total_time=300
```

A new parser needs a new fuzz target, and a case in the stable smoke pass.

## Code rules

- No `unsafe` code; the workspace lints forbid it.
- No panics on input from the air, the controller or MQTT: bounds-check every
  read, return errors, and never `unwrap` a value that came from outside.
- Check the controller's capabilities before using a feature.
- Every public item has a doc comment (`missing_docs` is on).
- New behavior comes with a test: a unit test against the specification's
  sample data, a Bumble end-to-end test, or an HCI replay case.
- Use maintained crates rather than writing your own: HCI types come from
  bt-hci, cryptography from RustCrypto. Assigned numbers come from the SIG's
  data through `bluetooth-numbers`; never type them in.
- Write from the Bluetooth specifications. Do not copy code from other
  Bluetooth stacks, whatever their license.

## Commits and pull requests

- One logical change per commit. The subject line says what the change does,
  in plain words, under 72 characters, for example
  `bluetooth-mesh-stack: GATT proxy client (ProxyBearer)`; the body says why.
- Say in the pull request what a user or a library user would notice: it
  goes into the
  [release notes](https://github.com/pulzar-net/bluetooth-bridge/releases).
  There is no changelog file; a release's notes are its annotated tag's
  message (`git tag -a vX.Y.Z --cleanup=whitespace -F notes.md`), which the
  release workflow publishes.
- Update the README and `docs/` when you change behavior, a configuration
  key or an MQTT topic.
- Sign off every commit (see below).

CI must pass before a pull request is merged: the tests, fuzzing and the
cross builds. Pull requests are squash-merged, so the pull
request's title and description become the commit on `main`: write them
as you would a commit message.

## Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin
1.1](https://developercertificate.org): by signing off a commit, you certify
that you wrote it, or otherwise have the right to submit it under the
project's MIT license. Sign off with `git commit -s`, which adds a line like:

```text
Signed-off-by: Your Name <you@example.com>
```

using your real name. Commits without a sign-off cannot be merged.

## License

By contributing, you agree that your contributions are licensed under the
[MIT license](LICENSE).
