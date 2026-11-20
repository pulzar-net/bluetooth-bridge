#!/usr/bin/env bash
# Runs the README's quick start as written, with Bumble's virtual controller
# in place of hci0 and a Bumble peer advertising BTHome readings as the
# sensor: download the release and check its sum, then write the README's
# configuration, run the bridge with the README's command, and wait for the
# sensor's Home Assistant discovery message and its readings. It runs twice:
# with the release binary the README downloads, and with this commit's build.
#
# Needs Linux, sudo, cargo, curl, jq, python3 (venv), and mosquitto with its
# clients. BUMBLE_PYTHON may name a Python that has Bumble installed;
# otherwise one is set up in a temporary virtual environment.
set -euo pipefail
cd "$(dirname "$0")/.."

# The body of the code block that follows `<!-- quickstart:NAME -->`.
block() {
    awk -v marker="<!-- quickstart:$1 -->" '
        $0 == marker { found = 1; next }
        found && /^```/ { if (inside) exit; inside = 1; next }
        inside { print }
    ' README.md
}

HCI_PORT=9000
SENSOR=F12233445566   # the Bumble peer's address in topic form
work="$(mktemp -d)"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do sudo kill "${pid}" 2>/dev/null || true; done
    rm -rf "${work}"
}
trap cleanup EXIT

# Wait up to $3 seconds for a message on topic $1 that the jq filter $2
# accepts. Retained messages count: the bridge may publish before we listen.
wait_for() {
    local deadline=$((SECONDS + $3))
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if mosquitto_sub -C 1 -W 5 -t "$1" 2>/dev/null | jq -e "$2" >/dev/null 2>&1; then
            return 0
        fi
    done
    echo "timed out waiting for $1 ($2)" >&2
    cat "${work}/bridge.log" "${work}/peer.log" >&2
    return 1
}

echo "--- 1. Download, verify and install the release"
download="$(block download)"
(cd "${work}" && bash -euxo pipefail -c "${download}")

echo "--- Bumble, and this commit's bridge"
python="${BUMBLE_PYTHON:-}"
if [ -z "${python}" ]; then
    python3 -m venv "${work}/venv"
    "${work}/venv/bin/pip" install -q -r tests/bumble/requirements.txt
    python="${work}/venv/bin/python"
fi
cargo build --locked -p bluetooth-bridge
build="$(pwd)/target/debug/bluetooth-bridge"

# A fresh broker for each run, so no retained message from an earlier run
# can satisfy a check. The README's commands use the default port.
sudo systemctl stop mosquitto 2>/dev/null || true

for bridge in bluetooth-bridge "${build}"; do
    echo "=== quick start with ${bridge}"
    sudo rm -rf /var/lib/bluetooth-bridge
    mosquitto -p 1883 >"${work}/broker.log" 2>&1 &
    pids+=("$!")
    # A virtual controller on TCP, and a peer advertising BTHome readings.
    "${python}" tests/bumble/peer.py scan_legacy "${HCI_PORT}" >"${work}/peer.log" 2>&1 </dev/null &
    pids+=("$!")
    sleep 3

    echo "--- 3. The README's configuration, with the virtual controller as the transport"
    sudo mkdir -p /etc/bluetooth-bridge
    block config \
        | sed "s|^transport = .*|transport = \"tcp:127.0.0.1:${HCI_PORT}\"|" \
        | sudo tee /etc/bluetooth-bridge/config.toml

    echo "--- 4. Run"
    run="$(block run | sed "s|^sudo bluetooth-bridge |sudo ${bridge} |")"
    bash -c "${run}" >"${work}/bridge.log" 2>&1 &
    wait_for bluetooth/bridge/state '.state == "online"' 30

    echo "--- 5. The sensor appears"
    wait_for "homeassistant/sensor/bluetooth_$(echo "${SENSOR}" | tr 'A-F' 'a-f')/temperature/config" \
        '.state_topic == "bluetooth/device/'"${SENSOR}"'"' 60
    wait_for "bluetooth/device/${SENSOR}" '.temperature == 25.06' 60

    sudo pkill -f -- "bluetooth-bridge --config" || true
    sleep 1
    for pid in "${pids[@]}"; do kill "${pid}" 2>/dev/null || true; done
    pids=()
    sleep 1
done
echo "quick start: ok"
