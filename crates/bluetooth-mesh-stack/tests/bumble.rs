//! Mesh end to end over real HCI: two of our hosts on one Bumble link (a
//! virtual controller each, over H4 on TCP), one a provisioner and one a
//! node, through the advertising bearer. Bumble has no Mesh of its own;
//! this checks our provisioner against our node on the air. Skips without
//! `BUMBLE_PYTHON` unless `BUMBLE_REQUIRED` is set (CI).

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bluetooth_host::{Dedup, Host, HostConfig, ScanConfig, TransportSpec};
use bluetooth_mesh_stack::provisioning::{Auth, Capabilities};
use bluetooth_mesh_stack::proxy::{ProxyBearer, ProxyServer};
use bluetooth_mesh_stack::runtime::{
    run_host_bearer, Bearer, HexKey, HostBearer, Mesh, MeshEvent, NodeRecord, Store,
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn open(port: u16) -> Host {
    Host::open(
        &TransportSpec::Tcp(format!("127.0.0.1:{port}")),
        HostConfig {
            use_public_address: false,
            ..HostConfig::default()
        },
    )
    .await
    .unwrap()
}

async fn host(port: u16) -> Host {
    let h = open(port).await;
    h.start_scan(ScanConfig {
        dedup: Dedup::Off,
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    h
}

/// Two virtual controllers on one link, for two hosts under test: their
/// ports, and the script (kept alive until dropped). None to skip.
async fn two_controllers() -> Option<(u16, u16, tokio::process::Child)> {
    let py = match std::env::var("BUMBLE_PYTHON") {
        Ok(p) => p,
        Err(_) if std::env::var("BUMBLE_REQUIRED").is_ok() => panic!("BUMBLE_PYTHON is not set"),
        Err(_) => {
            eprintln!("skipping: set BUMBLE_PYTHON to a Python with bumble installed");
            return None;
        }
    };
    let (p1, p2) = (free_port(), free_port());
    let mut child = tokio::process::Command::new(py)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/bumble/peer.py"
        ))
        .arg("idle")
        .arg(p1.to_string())
        .arg(json!({ "port2": p2 }).to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    loop {
        let l = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(&l).unwrap_or(Value::Null);
        if v["event"] == "ready" {
            break;
        }
    }
    // Drained, so the script never blocks on (or dies of) a full pipe.
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    Some((p1, p2, child))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provisioner_provisions_configures_and_controls_a_node() {
    let Some((p1, p2, mut child)) = two_controllers().await else {
        return;
    };
    let mut stdin = child.stdin.take().unwrap();

    let (ha, hb) = (host(p1).await, host(p2).await);
    let dir = tempfile::tempdir().unwrap();
    let prov = Mesh::open(
        HostBearer::new(ha.clone()),
        Some(dir.path().join("p")),
        [0; 16],
    )
    .unwrap();
    let uuid = [0x5e; 16];
    let node = Mesh::open(
        HostBearer::new(hb.clone()),
        Some(dir.path().join("n")),
        uuid,
    )
    .unwrap();
    tokio::spawn(run_host_bearer(ha, prov.clone()));
    tokio::spawn(run_host_bearer(hb, node.clone()));

    prov.create_network();
    let mut events = prov.events();
    let n = node.clone();
    let caps = Capabilities {
        elements: 1,
        algorithms: 1,
        public_key_oob: false,
        static_oob: false,
        output_oob: (0, 0),
        input_oob: (0, 0),
    };
    tokio::spawn(async move { n.wait_for_provisioning(caps, None).await });
    let seen = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(MeshEvent::Unprovisioned { uuid: u, .. }) = events.recv().await {
                break u;
            }
        }
    })
    .await
    .expect("the node's unprovisioned beacon");
    assert_eq!(seen, uuid);

    let rec = tokio::time::timeout(Duration::from_secs(120), prov.provision(uuid, Auth::None))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.address, 0x0002);
    let comp = tokio::time::timeout(Duration::from_secs(60), prov.configure(&rec))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(comp.elements.len(), 1);
    assert!(tokio::time::timeout(
        Duration::from_secs(30),
        prov.onoff_set(rec.address, true, 1)
    )
    .await
    .unwrap()
    .unwrap());
    assert!(node.store().onoff);
    let _ = stdin.write_all(b"{\"op\": \"stop\"}\n").await;
}

/// A provisioned network written to two stores: the provisioner (0x0001)
/// knows the node (0x0002), whose Generic OnOff Server is bound.
fn network(dir: &std::path::Path) {
    let (net, app, dev) = ([0x11; 16], [0x22; 16], [0x33; 16]);
    let write = |name: &str, s: &Store| {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("mesh.json"), serde_json::to_vec(s).unwrap()).unwrap();
    };
    write(
        "p",
        &Store {
            address: 0x0001,
            net_keys: vec![(0, HexKey(net))],
            app_keys: vec![(0, 0, HexKey(app))],
            nodes: vec![NodeRecord {
                uuid: [0x5e; 16],
                address: 0x0002,
                elements: 1,
                device_key: dev,
            }],
            ..Store::default()
        },
    );
    write(
        "n",
        &Store {
            address: 0x0002,
            net_keys: vec![(0, HexKey(net))],
            app_keys: vec![(0, 0, HexKey(app))],
            device_key: Some(HexKey(dev)),
            bindings: vec![(0x0002, 0x1000, 0)],
            ..Store::default()
        },
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_controls_a_node_through_its_proxy() {
    let Some((p1, p2, _child)) = two_controllers().await else {
        return;
    };
    let (ha, hb) = (open(p1).await, open(p2).await);
    let dir = tempfile::tempdir().unwrap();
    network(dir.path());

    // The node: reachable only through its proxy.
    let server = ProxyServer::new(hb.clone(), None).await.unwrap();
    let node = Mesh::open(
        server.clone() as Arc<dyn Bearer>,
        Some(dir.path().join("n")),
        [0x5e; 16],
    )
    .unwrap();
    let s = server.clone();
    let n = node.clone();
    tokio::spawn(async move { s.run(n).await });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The client: connects to it by address and speaks through it.
    let bearer = tokio::time::timeout(
        Duration::from_secs(20),
        ProxyBearer::connect(&ha, hb.address()),
    )
    .await
    .unwrap()
    .unwrap();
    let client = Mesh::open(
        bearer.clone() as Arc<dyn Bearer>,
        Some(dir.path().join("p")),
        [0; 16],
    )
    .unwrap();
    let b = bearer.clone();
    let c = client.clone();
    tokio::spawn(async move { b.run(c).await });

    for on in [true, false, true] {
        let present = tokio::time::timeout(
            Duration::from_secs(20),
            client.onoff_set(0x0002, on, u8::from(on)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(present, on);
        assert_eq!(node.store().onoff, on);
    }
}
