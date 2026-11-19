//! End-to-end tests against Google's Bumble: a virtual controller for the
//! host under test (over H4 on TCP, as a real controller would be reached)
//! and a scripted peer on the same simulated link (`tests/bumble/peer.py`).
//!
//! Bumble's virtual controller models the air coarsely (0.0.236): it reports
//! every advertisement as an extended connectable one with SID 0, and echoes
//! the advertising data as the scan response. What it cannot carry (SIDs,
//! the legacy bit, distinct scan response data, fragmentation) is covered by
//! the HCI replay tests in `replay.rs`.
//!
//! Set `BUMBLE_PYTHON` to a Python with `bumble` installed
//! (`pip install -r tests/bumble/requirements.txt`). Without it these tests
//! skip, unless `BUMBLE_REQUIRED` is set (CI), when they fail.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bluetooth_adv::beacon::{self, Beacon};
use bluetooth_adv::Uuid;
use bluetooth_host::gatt::server::{Access, CharacteristicDef, ServiceDef};
use bluetooth_host::{
    Address, AdvertisingParams, ConnEvent, ConnectParams, Connection, Dedup, FixedAgent, Host,
    HostConfig, HostEvent, IoCapability, OobData, ParamsRequest, PeriodicParams, ScanConfig,
    TransportSpec,
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::broadcast;

const PEER: &str = "F1:22:33:44:55:66";
const SERVICE: &str = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
const CHAR_LONG: &str = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
const CHAR_WRITE: &str = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";
const CHAR_NOTIFY: &str = "6e400004-b5a3-f393-e0a9-e50e24dcca9e";
const PASSKEY: u32 = 123_456;
const WAIT: Duration = Duration::from_secs(30);

struct Peer {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    port: u16,
}

fn python() -> Option<String> {
    match std::env::var("BUMBLE_PYTHON") {
        Ok(p) => Some(p),
        Err(_) if std::env::var("BUMBLE_REQUIRED").is_ok() => {
            panic!("BUMBLE_REQUIRED is set but BUMBLE_PYTHON is not")
        }
        Err(_) => {
            eprintln!("skipping: set BUMBLE_PYTHON to a Python with bumble installed");
            None
        }
    }
}

impl Peer {
    async fn start(scenario: &str, args: Value) -> Option<Peer> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let py = python()?;
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/bumble/peer.py");
        let mut child = Command::new(py)
            .arg(script)
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
        let stdout = child.stdout.take().unwrap();
        let mut p = Peer {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
            port,
        };
        p.expect("ready").await;
        Some(p)
    }

    async fn expect(&mut self, event: &str) -> Value {
        loop {
            let line = tokio::time::timeout(WAIT, self.lines.next_line())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for the peer's {event:?}"))
                .expect("read the peer's output")
                .unwrap_or_else(|| panic!("the peer exited before {event:?}"));
            let v: Value =
                serde_json::from_str(&line).unwrap_or(json!({"event": "log", "line": line}));
            if v["event"] == "error" {
                panic!("the peer failed: {}", v["message"]);
            }
            if v["event"] == event {
                return v;
            }
            eprintln!("peer: {line}");
        }
    }

    async fn send(&mut self, v: Value) {
        self.stdin
            .write_all(format!("{v}\n").as_bytes())
            .await
            .unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Opens the host under test on the peer's virtual controller. It runs
    /// on its static random address: Bumble's simulated link tags LE data
    /// with the sender's random address only.
    async fn host(&self, config: HostConfig) -> Host {
        Host::open(
            &TransportSpec::Tcp(format!("127.0.0.1:{}", self.port)),
            HostConfig {
                use_public_address: false,
                ..config
            },
        )
        .await
        .expect("open the host on the Bumble controller")
    }

    /// Tells the peer where the host under test is.
    async fn target(&mut self, host: &Host) {
        let a = host.address().to_string();
        self.send(json!({"op": "target", "address": a})).await;
    }

    async fn finish(mut self) {
        self.send(json!({"op": "stop"})).await;
        self.expect("done").await;
        let status = tokio::time::timeout(WAIT, self.child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(status.success(), "the peer exited with {status}");
    }
}

async fn wait_for<T>(
    rx: &mut broadcast::Receiver<HostEvent>,
    mut f: impl FnMut(&HostEvent) -> Option<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(e)) => {
                if let Some(t) = f(&e) {
                    return t;
                }
            }
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(e)) => panic!("host events: {e}"),
            Err(_) => panic!("timed out waiting for a host event"),
        }
    }
}

async fn wait_conn<T>(
    rx: &mut broadcast::Receiver<ConnEvent>,
    mut f: impl FnMut(&ConnEvent) -> Option<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(e)) => {
                if let Some(t) = f(&e) {
                    return t;
                }
            }
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(e)) => panic!("connection events: {e}"),
            Err(_) => panic!("timed out waiting for a connection event"),
        }
    }
}

fn peer_address() -> Address {
    format!("{PEER}/random").parse().unwrap()
}

fn config(io: IoCapability, mitm: bool, agent: FixedAgent) -> HostConfig {
    HostConfig {
        io_capability: io,
        mitm,
        agent: Arc::new(agent),
        allow_debug_keys: false,
        ..HostConfig::default()
    }
}

fn fixed() -> FixedAgent {
    FixedAgent {
        passkey: Some(PASSKEY),
        confirm: true,
        oob: None,
    }
}

// ------------------------------------------------------------------ observer

#[tokio::test(flavor = "multi_thread")]
async fn scans_legacy_advertising_with_scan_response() {
    let Some(mut peer) = Peer::start("scan_legacy", json!({})).await else {
        return;
    };
    peer.expect("advertising").await;
    let host = peer.host(HostConfig::default()).await;
    let mut ev = host.events();
    host.start_scan(ScanConfig {
        active: true,
        dedup: Dedup::Off,
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    let r = wait_for(&mut ev, |e| match e {
        HostEvent::Advertisement(r) if r.address == peer_address() && r.scan_response.is_some() => {
            Some(r.clone())
        }
        _ => None,
    })
    .await;
    assert!(r.connectable, "{r:?}");
    let adv = r.advertisement();
    assert_eq!(adv.local_name.as_ref().unwrap().name, "bumble-peer");
    assert_eq!(adv.manufacturer_data[0].data, b"hello");
    let beacons = beacon::decode(&adv, &beacon::Context::for_address(r.address.bytes));
    let Some(Beacon::BtHome(b)) = beacons.first() else {
        panic!("no BTHome in {beacons:?}")
    };
    assert_eq!(b.measurements[0].name, "temperature");
    assert_eq!(b.measurements[0].value, 25.06);

    // Duplicate filtering by us: an unchanging device is reported once.
    host.start_scan(ScanConfig {
        active: true,
        dedup: Dedup::Changes,
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    let mut ev = host.events();
    let mut n = 0u32;
    let end = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Ok(e)) = tokio::time::timeout_at(end, ev.recv()).await {
        if matches!(e, HostEvent::Advertisement(r) if r.address == peer_address()) {
            n += 1;
        }
    }
    // Once for the advertisement, once more when its scan response joins it.
    assert!(
        (1..=2).contains(&n),
        "{n} reports with duplicate filtering on"
    );
    host.stop_scan().await.unwrap();
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn scans_extended_advertising() {
    let Some(mut peer) = Peer::start("scan_extended", json!({})).await else {
        return;
    };
    let a = peer.expect("advertising").await;
    let host = peer.host(HostConfig::default()).await;
    assert!(host.capabilities().extended_scanning() && host.capabilities().periodic_advertising());
    let mut ev = host.events();
    host.start_scan(ScanConfig::default()).await.unwrap();
    let r = wait_for(&mut ev, |e| match e {
        HostEvent::Advertisement(r) if r.address == peer_address() => Some(r.clone()),
        _ => None,
    })
    .await;
    assert_eq!(r.data.len() as u64, a["length"].as_u64().unwrap());
    let adv = r.advertisement();
    assert_eq!(adv.local_name.unwrap().name, "bumble-extended");
    assert_eq!(adv.manufacturer_data[0].data.len(), 180);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn syncs_to_periodic_advertising() {
    let Some(mut peer) = Peer::start("periodic", json!({})).await else {
        return;
    };
    peer.expect("advertising").await;
    let host = peer.host(HostConfig::default()).await;
    let mut ev = host.events();
    host.start_scan(ScanConfig::default()).await.unwrap();
    let r = wait_for(&mut ev, |e| match e {
        HostEvent::Advertisement(r) if r.address == peer_address() => Some(r.clone()),
        _ => None,
    })
    .await;
    // Bumble reports every set as SID 0; the peer's set is 7.
    let sync = host.sync_periodic(r.address, 7, 0, 2000).await.unwrap();
    let p = wait_for(&mut ev, |e| match e {
        HostEvent::PeriodicReport(p) if p.sync == sync => Some(p.clone()),
        _ => None,
    })
    .await;
    let adv = bluetooth_adv::Advertisement::parse(&p.data);
    assert_eq!(adv.manufacturer_data[0].data, b"periodic");
    host.terminate_sync(sync).await.unwrap();
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resolves_private_addresses_with_a_known_irk() {
    let irk = "ec0234a357c8ad05341010a60a397d9b";
    let Some(mut peer) = Peer::start("rpa", json!({ "irk": irk })).await else {
        return;
    };
    let a = peer.expect("advertising").await;
    let rpa: Address = format!(
        "{}/random",
        a["address"].as_str().unwrap().split('/').next().unwrap()
    )
    .parse()
    .unwrap();
    assert!(rpa.is_resolvable());
    let host = peer.host(HostConfig::default()).await;
    let identity: Address = "C0:FF:EE:00:00:01/random".parse().unwrap();
    // Bumble keeps keys least significant byte first.
    let le: [u8; 16] = hex::decode(irk).unwrap().try_into().unwrap();
    host.keys()
        .add_irk(identity, u128::from_le_bytes(le), Some("tag".into()))
        .unwrap();
    let mut ev = host.events();
    host.start_scan(ScanConfig::default()).await.unwrap();
    let r = wait_for(&mut ev, |e| match e {
        HostEvent::Advertisement(r) if r.address == rpa => Some(r.clone()),
        _ => None,
    })
    .await;
    assert_eq!(r.identity, Some(identity));
    assert_eq!(r.device(), identity);
    peer.finish().await;
}

// --------------------------------------------------------------- broadcaster

#[tokio::test(flavor = "multi_thread")]
async fn advertises_legacy_and_extended_sets() {
    let Some(mut peer) = Peer::start("observe", json!({})).await else {
        return;
    };
    let host = peer.host(HostConfig::default()).await;
    peer.target(&host).await;
    peer.expect("scanning").await;
    let legacy = hex::decode("020106 0b09 6c65676163792d736574".replace(' ', "")).unwrap();
    let set = host
        .advertise(
            &AdvertisingParams {
                legacy: Some(true),
                interval_min_ms: 20,
                interval_max_ms: 30,
                ..AdvertisingParams::default()
            },
            &legacy,
            &[],
        )
        .await
        .unwrap();
    let seen = peer.expect("advertisement").await;
    assert_eq!(seen["data"], hex::encode(&legacy));
    host.stop_advertising(set).await.unwrap();

    // An extended set with more than legacy advertising can carry.
    let mut long = vec![0x64, 0xff, 0xff, 0xff];
    long.extend((0..99).map(|i| i as u8));
    let set = host
        .advertise(
            &AdvertisingParams {
                legacy: Some(false),
                sid: 5,
                interval_min_ms: 20,
                interval_max_ms: 30,
                ..AdvertisingParams::default()
            },
            &long,
            &[],
        )
        .await
        .unwrap();
    let seen = loop {
        let s = peer.expect("advertisement").await;
        if s["data"] == hex::encode(&long) {
            break s;
        }
    };
    assert_eq!(seen["data"], hex::encode(&long));
    host.stop_advertising(set).await.unwrap();
    peer.finish().await;
}

// --------------------------------------------------- central and GATT client

async fn connect(host: &Host) -> Connection {
    host.connect(peer_address(), &ConnectParams::default())
        .await
        .expect("connect")
}

#[tokio::test(flavor = "multi_thread")]
async fn central_gatt_client() {
    let Some(mut peer) = Peer::start("peripheral", json!({})).await else {
        return;
    };
    peer.expect("advertising").await;
    let host = peer.host(HostConfig::default()).await;
    let conn = connect(&host).await;
    peer.expect("connected").await;
    let g = conn.gatt();
    let mtu = g.exchange_mtu(247).await.unwrap();
    assert!((23..=247).contains(&mtu), "{mtu}");

    let services = g.discover().await.unwrap();
    let s = services
        .iter()
        .find(|s| s.uuid == Uuid::parse(SERVICE).unwrap())
        .expect("the test service");
    let find = |u: &str| {
        s.characteristics
            .iter()
            .find(|c| c.uuid == Uuid::parse(u).unwrap())
            .unwrap()
            .clone()
    };
    let (long, write, notify) = (find(CHAR_LONG), find(CHAR_WRITE), find(CHAR_NOTIFY));
    assert!(notify.cccd().is_some());

    // A long read: 300 octets over several Read Blob requests.
    let mut want: Vec<u8> = (0..=255u8).collect();
    want.extend(0..44u8);
    assert_eq!(g.read(long.value_handle).await.unwrap(), want);

    // Write, write without response, and a long (prepared) write.
    g.write(write.value_handle, b"hello").await.unwrap();
    assert_eq!(peer.expect("written").await["value"], hex::encode("hello"));
    g.write_without_response(write.value_handle, b"quick")
        .await
        .unwrap();
    assert_eq!(peer.expect("written").await["value"], hex::encode("quick"));
    let big: Vec<u8> = (0..400u16).map(|i| (i % 251) as u8).collect();
    g.write(write.value_handle, &big).await.unwrap();
    assert_eq!(peer.expect("written").await["value"], hex::encode(&big));

    // Notifications, then indications (confirmed by us).
    let mut cev = conn.events();
    g.subscribe(&notify, true, false).await.unwrap();
    let v = wait_conn(&mut cev, |e| match e {
        ConnEvent::Notification {
            handle,
            value,
            indication: false,
        } if *handle == notify.value_handle => Some(value.clone()),
        _ => None,
    })
    .await;
    assert_eq!(v, b"notified");
    g.subscribe(&notify, false, true).await.unwrap();
    let v = wait_conn(&mut cev, |e| match e {
        ConnEvent::Notification {
            value,
            indication: true,
            ..
        } => Some(value.clone()),
        _ => None,
    })
    .await;
    assert_eq!(v, b"indicated");
    peer.expect("indication_confirmed").await;

    // Connection parameter update as central.
    let p = conn
        .update_params(ParamsRequest {
            interval_min: 40,
            interval_max: 56,
            latency: 0,
            timeout: 500,
        })
        .await
        .unwrap();
    assert!((40..=56).contains(&p.interval), "{p:?}");

    // PHY and data length: done when the controller can, refused cleanly when not.
    let caps = host.capabilities().clone();
    let r = tokio::time::timeout(
        WAIT,
        conn.set_phy(
            &[bluetooth_host::Phy::Le2m],
            &[bluetooth_host::Phy::Le2m],
            false,
        ),
    )
    .await
    .expect("a PHY update answers");
    if !caps.phy_update() {
        assert!(r.is_err());
    }
    let _ = tokio::time::timeout(WAIT, conn.set_data_length(251, 2120))
        .await
        .expect("DLE answers");

    conn.disconnect().await.unwrap();
    peer.expect("disconnected").await;
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn central_opens_an_l2cap_channel() {
    let Some(mut peer) = Peer::start("peripheral", json!({ "l2cap": true })).await else {
        return;
    };
    peer.expect("advertising").await;
    let host = peer.host(HostConfig::default()).await;
    let conn = connect(&host).await;
    let mut ch = conn.open_channel(0x0081, 1024).await.unwrap();
    assert_eq!(ch.peer_mtu(), 1024);
    let sdu: Vec<u8> = (0..600u16).map(|i| i as u8).collect();
    ch.send(&sdu).await.unwrap();
    assert_eq!(peer.expect("sdu").await["length"], 600);
    let echo = tokio::time::timeout(WAIT, ch.recv())
        .await
        .unwrap()
        .unwrap();
    let mut rev = sdu.clone();
    rev.reverse();
    assert_eq!(echo, rev);
    ch.close().await.unwrap();
    peer.finish().await;
}

// ------------------------------------------------ peripheral and GATT server

async fn serve_and_advertise(host: &Host) -> (u16, u16, u16) {
    let h = host
        .gatt_server()
        .add(&ServiceDef {
            uuid: Uuid::parse(SERVICE).unwrap(),
            primary: true,
            characteristics: vec![
                CharacteristicDef {
                    uuid: Uuid::parse(CHAR_LONG).unwrap(),
                    properties: vec!["read".into()],
                    read: Access::Open,
                    write: Access::Never,
                    value: b"from the dut".to_vec(),
                    max_len: 512,
                    description: Some("a value".into()),
                    descriptors: vec![],
                },
                CharacteristicDef {
                    uuid: Uuid::parse(CHAR_WRITE).unwrap(),
                    properties: vec![
                        "read".into(),
                        "write".into(),
                        "write_without_response".into(),
                    ],
                    read: Access::Open,
                    write: Access::Open,
                    value: vec![],
                    max_len: 512,
                    description: None,
                    descriptors: vec![],
                },
                CharacteristicDef {
                    uuid: Uuid::parse(CHAR_NOTIFY).unwrap(),
                    properties: vec!["read".into(), "notify".into(), "indicate".into()],
                    read: Access::Open,
                    write: Access::Never,
                    value: vec![0],
                    max_len: 64,
                    description: None,
                    descriptors: vec![],
                },
            ],
        })
        .await
        .unwrap();
    let data = hex::decode("020106 0809 6475742d676174".replace(' ', "")).unwrap();
    host.advertise(
        &AdvertisingParams {
            connectable: true,
            legacy: Some(true),
            interval_min_ms: 20,
            interval_max_ms: 30,
            ..AdvertisingParams::default()
        },
        &data,
        &[],
    )
    .await
    .unwrap();
    (
        h.characteristics[0].1,
        h.characteristics[1].1,
        h.characteristics[2].1,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn peripheral_gatt_server() {
    let Some(mut peer) = Peer::start(
        "central",
        json!({"steps": ["gatt"], "service": SERVICE,
               "read": CHAR_LONG, "write": CHAR_WRITE, "notify": CHAR_NOTIFY}),
    )
    .await
    else {
        return;
    };
    let host = peer.host(HostConfig::default()).await;
    let mut ev = host.events();
    let (_, write_h, notify_h) = serve_and_advertise(&host).await;
    peer.target(&host).await;
    peer.expect("connected").await;
    let conn = wait_for(&mut ev, |e| match e {
        HostEvent::Connected(c) => Some(c.clone()),
        _ => None,
    })
    .await;
    assert_eq!(conn.role(), bluetooth_host::Role::Peripheral);
    assert!(peer.expect("mtu").await["mtu"].as_u64().unwrap() > 23);
    assert_eq!(
        peer.expect("read").await["value"],
        hex::encode("from the dut")
    );
    let w1 = wait_for(&mut ev, |e| match e {
        HostEvent::GattWrite {
            attribute, value, ..
        } if *attribute == write_h => Some(value.clone()),
        _ => None,
    })
    .await;
    assert_eq!(w1, b"from bumble");
    let w2 = wait_for(&mut ev, |e| match e {
        HostEvent::GattWrite {
            attribute, value, ..
        } if *attribute == write_h => Some(value.clone()),
        _ => None,
    })
    .await;
    assert_eq!(w2, (0..200u8).collect::<Vec<_>>());
    peer.expect("wrote").await;
    assert_eq!(host.gatt_server().value(write_h).unwrap(), w2);
    wait_for(&mut ev, |e| match e {
        HostEvent::GattSubscription {
            attribute,
            notify: true,
            ..
        } if *attribute == notify_h => Some(()),
        _ => None,
    })
    .await;
    assert_eq!(
        host.gatt_server()
            .notify(notify_h, b"from the dut")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        peer.expect("notification").await["value"],
        hex::encode("from the dut")
    );
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peripheral_accepts_an_l2cap_channel() {
    let Some(mut peer) = Peer::start("central", json!({"steps": ["l2cap"]})).await else {
        return;
    };
    let host = peer.host(HostConfig::default()).await;
    let mut server = host.listen_channel(0x0083, 1024);
    serve_and_advertise(&host).await;
    peer.target(&host).await;
    let mut ch = tokio::time::timeout(WAIT, server.recv())
        .await
        .unwrap()
        .unwrap();
    let sdu = tokio::time::timeout(WAIT, ch.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sdu.len(), 512);
    let mut rev = sdu.clone();
    rev.reverse();
    ch.send(&rev).await.unwrap();
    assert_eq!(peer.expect("echo").await["ok"], true);
    peer.finish().await;
}

// ------------------------------------------------------------------- pairing

/// Pairs as central with a peer peripheral configured by `pairing`; returns
/// the resulting security.
async fn pair_as_central(
    pairing: Value,
    config: HostConfig,
) -> Option<(bluetooth_host::Security, Host, Peer, Value)> {
    let mut peer = Peer::start("peripheral", json!({ "pairing": pairing })).await?;
    let oob = if pairing["oob"] == "sc" {
        Some(peer.expect("oob").await)
    } else {
        None
    };
    let adv = peer.expect("advertising").await;
    let mut config = config;
    if let Some(o) = oob {
        let le = |k: &str| {
            u128::from_le_bytes(
                hex::decode(o[k].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        };
        config.agent = Arc::new(FixedAgent {
            passkey: None,
            confirm: true,
            oob: Some(OobData::SecureConnections {
                random: le("r"),
                confirm: le("c"),
            }),
        });
    }
    let host = peer.host(config).await;
    let conn = connect(&host).await;
    let s = conn.pair().await.expect("pairing");
    peer.expect("paired").await;
    Some((s, host, peer, adv))
}

fn check_bond(host: &Host, peer_irk: &Value, sc: bool) {
    let bonds = host.keys().bonds();
    assert_eq!(bonds.len(), 1, "{bonds:?}");
    let b = &bonds[0];
    assert!(b.ltk.is_some(), "no LTK stored");
    assert_eq!(b.secure_connections, sc);
    // Bumble distributes its IRK; it must be the one it advertises with.
    let irk = u128::from_str_radix(peer_irk.as_str().unwrap(), 16).unwrap();
    let mut le = irk.to_be_bytes();
    le.reverse();
    let as_le = u128::from_be_bytes(le);
    assert!(
        b.irk == Some(irk) || b.irk == Some(as_le),
        "IRK {:x?}",
        b.irk
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_sc_just_works_bonds_and_reencrypts() {
    let Some((s, host, mut peer, adv)) = pair_as_central(
        json!({"sc": true, "mitm": false, "io": "no_input_no_output"}),
        config(IoCapability::NoInputNoOutput, false, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!((s.level(), s.secure_connections, s.bonded), (2, true, true));
    check_bond(&host, &adv["irk"], true);

    // Reconnect: the stored key encrypts the link with no new pairing.
    let conn = host.connections().pop().unwrap();
    conn.disconnect().await.unwrap();
    peer.expect("disconnected").await;
    let mut ev = host.events();
    let conn = connect(&host).await;
    let s = conn.secure().await.unwrap();
    assert!(s.encrypted && s.bonded);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if let Ok(HostEvent::Paired { .. }) = ev.recv().await {
                    break;
                }
            }
        })
        .await
        .is_err(),
        "re-encryption must not pair again"
    );
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_sc_numeric_comparison() {
    let Some((s, host, peer, adv)) = pair_as_central(
        json!({"sc": true, "mitm": true, "io": "display_yes_no"}),
        config(IoCapability::DisplayYesNo, true, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!((s.level(), s.authenticated), (4, true));
    check_bond(&host, &adv["irk"], true);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_sc_passkey_we_type() {
    let Some((s, host, peer, adv)) = pair_as_central(
        json!({"sc": true, "mitm": true, "io": "display_only"}),
        config(IoCapability::KeyboardOnly, true, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!(s.level(), 4);
    check_bond(&host, &adv["irk"], true);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_sc_passkey_peer_types() {
    let Some((s, _host, peer, _)) = pair_as_central(
        json!({"sc": true, "mitm": true, "io": "keyboard_only"}),
        config(IoCapability::DisplayOnly, true, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!(s.level(), 4);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_sc_out_of_band() {
    let Some((s, _host, peer, _)) = pair_as_central(
        json!({"sc": true, "mitm": true, "io": "no_input_no_output", "oob": "sc"}),
        config(IoCapability::NoInputNoOutput, true, fixed()),
    )
    .await
    else {
        return;
    };
    assert!(s.authenticated && s.secure_connections);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_legacy_just_works() {
    let Some((s, host, peer, adv)) = pair_as_central(
        json!({"sc": false, "mitm": false, "io": "no_input_no_output"}),
        config(IoCapability::NoInputNoOutput, false, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!((s.level(), s.secure_connections), (2, false));
    check_bond(&host, &adv["irk"], false);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_legacy_passkey() {
    let Some((s, host, peer, adv)) = pair_as_central(
        json!({"sc": false, "mitm": true, "io": "display_only"}),
        config(IoCapability::KeyboardOnly, true, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!((s.level(), s.secure_connections), (3, false));
    check_bond(&host, &adv["irk"], false);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_legacy_out_of_band() {
    let tk = "00112233445566778899aabbccddeeff";
    let tk_bytes: [u8; 16] = hex::decode(tk).unwrap().try_into().unwrap();
    let Some((s, _host, peer, _)) = pair_as_central(
        json!({"sc": false, "mitm": true, "io": "no_input_no_output", "oob": "legacy", "tk": tk}),
        config(
            IoCapability::NoInputNoOutput,
            true,
            FixedAgent {
                passkey: None,
                confirm: true,
                oob: Some(OobData::Legacy(tk_bytes)),
            },
        ),
    )
    .await
    else {
        return;
    };
    assert_eq!((s.level(), s.secure_connections), (3, false));
    peer.finish().await;
}

/// Pairs as peripheral: the peer (central) starts it.
async fn pair_as_peripheral(
    pairing: Value,
    config: HostConfig,
) -> Option<(bluetooth_host::Security, Host, Peer, Value)> {
    let mut peer = Peer::start("central", json!({"steps": ["pair"], "pairing": pairing})).await?;
    let host = peer.host(config).await;
    let mut ev = host.events();
    serve_and_advertise(&host).await;
    peer.target(&host).await;
    let s = wait_for(&mut ev, |e| match e {
        HostEvent::Paired { security, .. } => Some(*security),
        HostEvent::PairingFailed { reason, .. } => panic!("pairing failed: {reason}"),
        _ => None,
    })
    .await;
    let p = peer.expect("paired").await;
    Some((s, host, peer, p))
}

#[tokio::test(flavor = "multi_thread")]
async fn responds_to_sc_just_works_and_distributes_our_irk() {
    let Some((s, host, peer, p)) = pair_as_peripheral(
        json!({"sc": true, "mitm": false, "io": "no_input_no_output"}),
        config(IoCapability::NoInputNoOutput, false, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!((s.level(), s.bonded), (2, true));
    assert_eq!(p["encrypted"], true);
    // The peer got our IRK (Bumble reports it least significant byte first).
    let irk = host.keys().local_irk();
    let got = p["irk"].as_str().expect("an IRK");
    assert!(
        got == hex::encode(irk.to_le_bytes()) || got == format!("{irk:032x}"),
        "{got}"
    );
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn responds_to_sc_passkey() {
    let Some((s, _host, peer, _)) = pair_as_peripheral(
        json!({"sc": true, "mitm": true, "io": "keyboard_only"}),
        config(IoCapability::DisplayOnly, true, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!(s.level(), 4);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn responds_to_sc_numeric_comparison() {
    let Some((s, _host, peer, _)) = pair_as_peripheral(
        json!({"sc": true, "mitm": true, "io": "display_yes_no"}),
        config(IoCapability::DisplayYesNo, true, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!(s.level(), 4);
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn responds_to_legacy_passkey() {
    let Some((s, _host, peer, _)) = pair_as_peripheral(
        json!({"sc": false, "mitm": true, "io": "keyboard_only"}),
        config(IoCapability::DisplayOnly, true, fixed()),
    )
    .await
    else {
        return;
    };
    assert_eq!((s.level(), s.secure_connections), (3, false));
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peripheral_asks_for_connection_parameters() {
    let Some(mut peer) = Peer::start("central", json!({"steps": []})).await else {
        return;
    };
    let host = peer.host(HostConfig::default()).await;
    let mut ev = host.events();
    serve_and_advertise(&host).await;
    peer.target(&host).await;
    let conn = wait_for(&mut ev, |e| match e {
        HostEvent::Connected(c) => Some(c.clone()),
        _ => None,
    })
    .await;
    let p = conn
        .update_params(ParamsRequest {
            interval_min: 30,
            interval_max: 40,
            latency: 0,
            timeout: 400,
        })
        .await
        .unwrap();
    assert!((30..=40).contains(&p.interval), "{p:?}");
    peer.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn starts_a_periodic_train() {
    let Some(mut peer) = Peer::start("observe", json!({})).await else {
        return;
    };
    let host = peer.host(HostConfig::default()).await;
    peer.target(&host).await;
    peer.expect("scanning").await;
    let set = host
        .advertise(
            &AdvertisingParams {
                legacy: Some(false),
                sid: 2,
                interval_min_ms: 20,
                interval_max_ms: 30,
                ..AdvertisingParams::default()
            },
            &hex::decode("0509706572").unwrap(),
            &[],
        )
        .await
        .unwrap();
    host.start_periodic(
        set,
        &PeriodicParams::default(),
        &hex::decode("05ffffff6869").unwrap(),
    )
    .await
    .unwrap();
    peer.expect("advertisement").await;
    host.stop_periodic(set).await.unwrap();
    host.stop_all_advertising().await.unwrap();
    peer.finish().await;
}
