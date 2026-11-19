//! The whole bridge, end to end: an MQTT broker (rumqttd, in process), a
//! Bumble virtual controller with a scripted peer (`tests/bumble/peer.py`),
//! and `bluetooth_bridge::run`. Skips without `BUMBLE_PYTHON`, unless
//! `BUMBLE_REQUIRED` is set.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use bluetooth_bridge::Config;
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use serde_json::{json, Value as Json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

const PEER_ID: &str = "F12233445566";
const SERVICE: &str = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn start_broker() -> SocketAddr {
    let addr = free_port();
    let mut servers = HashMap::new();
    servers.insert(
        "v4".to_string(),
        rumqttd::ServerSettings {
            name: "v4".into(),
            listen: addr,
            tls: None,
            next_connection_delay_ms: 1,
            connections: rumqttd::ConnectionSettings {
                connection_timeout_ms: 5000,
                max_payload_size: 256 * 1024,
                max_inflight_count: 200,
                auth: None,
                external_auth: None,
                dynamic_filters: true,
            },
        },
    );
    let config = rumqttd::Config {
        id: 0,
        router: rumqttd::RouterConfig {
            max_connections: 16,
            max_outgoing_packet_count: 200,
            max_segment_size: 16 * 1024 * 1024,
            max_segment_count: 10,
            ..Default::default()
        },
        v4: Some(servers),
        ..Default::default()
    };
    std::thread::spawn(move || {
        let mut broker = rumqttd::Broker::new(config);
        let _ = broker.start();
    });
    addr
}

/// The scripted Bumble peer; killed when dropped.
struct Peer {
    _child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    port: u16,
}

impl Peer {
    async fn start(scenario: &str, args: Json) -> Option<Peer> {
        let py = match std::env::var("BUMBLE_PYTHON") {
            Ok(p) => p,
            Err(_) if std::env::var("BUMBLE_REQUIRED").is_ok() => {
                panic!("BUMBLE_PYTHON is not set")
            }
            Err(_) => {
                eprintln!("skipping: set BUMBLE_PYTHON to a Python with bumble installed");
                return None;
            }
        };
        let port = free_port().port();
        let mut child = Command::new(py)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/bumble/peer.py"
            ))
            .arg(scenario)
            .arg(port.to_string())
            .arg(args.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start the Bumble peer");
        let stdin = child.stdin.take().unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut p = Peer {
            _child: child,
            stdin,
            lines,
            port,
        };
        p.expect("ready").await;
        Some(p)
    }

    async fn expect(&mut self, event: &str) -> Json {
        loop {
            let line = tokio::time::timeout(Duration::from_secs(30), self.lines.next_line())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for the peer's {event:?}"))
                .unwrap()
                .unwrap_or_else(|| panic!("the peer exited before {event:?}"));
            let v: Json = serde_json::from_str(&line).unwrap_or(Json::Null);
            assert_ne!(v["event"], "error", "the peer failed: {line}");
            if v["event"] == event {
                return v;
            }
        }
    }

    async fn stop(mut self) {
        let _ = self.stdin.write_all(b"{\"op\": \"stop\"}\n").await;
        self.expect("done").await;
    }
}

struct Watcher {
    client: AsyncClient,
    rx: mpsc::UnboundedReceiver<(String, Vec<u8>)>,
    seen: Vec<(String, Json)>,
}

impl Watcher {
    async fn connect(broker: SocketAddr) -> Watcher {
        let mut options = MqttOptions::new("e2e-watcher", broker.ip().to_string(), broker.port());
        options.set_keep_alive(Duration::from_secs(10));
        options.set_max_packet_size(256 * 1024, 256 * 1024);
        let (client, mut event_loop) = AsyncClient::new(options, 100);
        let (tx, rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let mut ready = Some(ready_tx);
        tokio::spawn(async move {
            loop {
                match event_loop.poll().await {
                    Ok(Event::Incoming(Packet::SubAck(_))) => {
                        if let Some(r) = ready.take() {
                            let _ = r.send(());
                        }
                    }
                    Ok(Event::Incoming(Packet::Publish(p))) => {
                        let _ = tx.send((p.topic.clone(), p.payload.to_vec()));
                    }
                    Ok(_) => {}
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        });
        client.subscribe("#", QoS::AtLeastOnce).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        Watcher {
            client,
            rx,
            seen: Vec::new(),
        }
    }

    async fn wait(&mut self, topic: &str, mut pred: impl FnMut(&Json) -> bool) -> Json {
        if let Some((_, v)) = self.seen.iter().find(|(t, v)| t == topic && pred(v)) {
            return v.clone();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let (t, payload) = tokio::time::timeout_at(deadline, self.rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting on {topic}"))
                .expect("watcher stopped");
            let value: Json = serde_json::from_slice(&payload).unwrap_or(Json::Null);
            self.seen.push((t.clone(), value.clone()));
            if t == topic && pred(&value) {
                return value;
            }
        }
    }

    async fn request(&mut self, op: &str, mut body: Json) -> Json {
        let transaction = format!("t-{op}-{}", self.seen.len());
        body["transaction"] = json!(transaction);
        self.client
            .publish(
                format!("bluetooth/bridge/request/{op}"),
                QoS::AtLeastOnce,
                false,
                serde_json::to_vec(&body).unwrap(),
            )
            .await
            .unwrap();
        let r = self
            .wait(&format!("bluetooth/bridge/response/{op}"), |v| {
                v["transaction"] == transaction
            })
            .await;
        assert_eq!(r["status"], "ok", "{op}: {r}");
        r["data"].clone()
    }
}

fn config(broker: SocketAddr, port: u16, data: &std::path::Path) -> Config {
    Config::parse(&format!(
        r#"
[adapter]
transport = "tcp:127.0.0.1:{port}"
random_address = true

[mqtt]
host = "{}"
port = {}
client_id = "bluetooth-bridge-e2e"

[scan]
active = true
dedup = "off"

[data]
dir = "{}"
"#,
        broker.ip(),
        broker.port(),
        data.display()
    ))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_advertisements_readings_and_discovery() {
    let Some(mut peer) = Peer::start("scan_legacy", json!({})).await else {
        return;
    };
    peer.expect("advertising").await;
    let broker = start_broker();
    let mut w = Watcher::connect(broker).await;
    let data = tempfile::tempdir().unwrap();
    let bridge = tokio::spawn(bluetooth_bridge::run(config(
        broker,
        peer.port,
        data.path(),
    )));

    w.wait("bluetooth/bridge/state", |v| v["state"] == "online")
        .await;
    let info = w.wait("bluetooth/bridge/info", |_| true).await;
    assert!(info["le_features"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "extended_advertising"));

    let scan = w.wait(&format!("bluetooth/scan/{PEER_ID}"), |_| true).await;
    assert_eq!(scan["name"], "bumble-peer");
    assert_eq!(scan["address"], "F1:22:33:44:55:66/random");
    assert_eq!(scan["beacons"][0]["format"], "bt_home");
    assert!(scan["rssi"].is_i64());

    let state = w
        .wait(&format!("bluetooth/device/{PEER_ID}"), |v| {
            v.get("temperature").is_some()
        })
        .await;
    assert_eq!(state["temperature"], 25.06);
    assert_eq!(state["humidity"], 50.55);

    let id = PEER_ID.to_lowercase();
    let disc = w
        .wait(
            &format!("homeassistant/sensor/bluetooth_{id}/temperature/config"),
            |_| true,
        )
        .await;
    assert_eq!(disc["device_class"], "temperature");
    assert_eq!(disc["unit_of_measurement"], "°C");
    assert_eq!(disc["state_topic"], format!("bluetooth/device/{PEER_ID}"));

    let r = w.request("info", json!({})).await;
    assert!(r["address"].as_str().unwrap().ends_with("/random"));
    let r = w.request("scan/stop", json!({})).await;
    assert_eq!(r, json!({}));
    bridge.abort();
    peer.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gatt_operations_over_mqtt() {
    let Some(mut peer) = Peer::start("peripheral", json!({})).await else {
        return;
    };
    peer.expect("advertising").await;
    let broker = start_broker();
    let mut w = Watcher::connect(broker).await;
    let data = tempfile::tempdir().unwrap();
    let bridge = tokio::spawn(bluetooth_bridge::run(config(
        broker,
        peer.port,
        data.path(),
    )));
    w.wait("bluetooth/bridge/state", |v| v["state"] == "online")
        .await;

    let c = w
        .request("connect", json!({"address": "F1:22:33:44:55:66/random"}))
        .await;
    let handle = c["handle"].as_u64().unwrap();
    w.wait("bluetooth/bridge/event", |v| v["type"] == "connected")
        .await;
    w.request("gatt/mtu", json!({"handle": handle, "mtu": 247}))
        .await;
    let services = w.request("gatt/discover", json!({"handle": handle})).await;
    let s = services
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["uuid"] == SERVICE)
        .expect("the test service");
    let chars = s["characteristics"].as_array().unwrap();
    let long = chars[0]["value_handle"].as_u64().unwrap();
    let write = chars[1]["value_handle"].as_u64().unwrap();
    let notify = chars[2]["value_handle"].as_u64().unwrap();
    let v = w
        .request("gatt/read", json!({"handle": handle, "attribute": long}))
        .await;
    assert_eq!(v["value"].as_str().unwrap().len(), 600, "300 octets, hex");
    w.request(
        "gatt/write",
        json!({"handle": handle, "attribute": write, "value": "6869"}),
    )
    .await;
    assert_eq!(peer.expect("written").await["value"], "6869");
    w.request(
        "gatt/subscribe",
        json!({"handle": handle, "attribute": notify, "notify": true}),
    )
    .await;
    let n = w
        .wait("bluetooth/bridge/event", |v| v["type"] == "notification")
        .await;
    assert_eq!(n["value"], hex::encode("notified"));
    w.request("pair", json!({"handle": handle})).await;
    let bonds = w.request("bonds", json!({})).await;
    assert_eq!(bonds.as_array().unwrap().len(), 1);
    assert!(bonds[0].get("ltk").is_none(), "keys are never published");
    w.request("disconnect", json!({"handle": handle})).await;
    bridge.abort();
    peer.stop().await;
}
