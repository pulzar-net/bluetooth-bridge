//! HCI replay tests: a scripted controller answers the host's commands and
//! sends exact event bytes, so behaviour that depends on what a real chip
//! says (SIDs, legacy bits, fragmented reports, scan responses, a Bluetooth 4
//! controller's limits) is checked byte for byte. Recorded traffic from
//! real controllers goes here too.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bluetooth_host::transport::{PacketReader, PacketWriter};
use bluetooth_host::{
    AdvertisingParams, ConnectParams, Dedup, Error, Host, HostConfig, HostEvent, Phy, ScanConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{broadcast, mpsc};

/// What the scripted controller claims to be.
#[derive(Clone)]
struct Chip {
    hci_version: u8,
    le_features: u64,
    adv_sets: u8,
}

/// A Bluetooth 4.1 controller like the Raspberry Pi 3's: encryption and
/// the connection parameters request, nothing from Bluetooth 5.
fn pi3() -> Chip {
    Chip {
        hci_version: 7,
        le_features: 0b11,
        adv_sets: 1,
    }
}

/// A Bluetooth 5 controller with extended and periodic advertising, 2M and coded PHY and DLE.
fn bt5() -> Chip {
    Chip {
        hci_version: 9,
        le_features: (1 << 0) | (1 << 1) | (1 << 5) | (1 << 8) | (1 << 11) | (1 << 12) | (1 << 13),
        adv_sets: 4,
    }
}

struct Controller {
    sent: Arc<Mutex<Vec<u16>>>,
    inject: mpsc::Sender<Vec<u8>>,
}

impl Controller {
    fn opcodes(&self) -> Vec<u16> {
        self.sent.lock().unwrap().clone()
    }

    async fn event(&self, bytes: Vec<u8>) {
        self.inject.send(bytes).await.unwrap();
    }
}

fn reply(chip: &Chip, opcode: u16) -> Option<Vec<u8>> {
    let mut r = vec![0u8];
    match opcode {
        0x1001 => r.extend([
            chip.hci_version,
            0,
            0,
            chip.hci_version,
            0x0f,
            0x00,
            0x34,
            0x12,
        ]),
        0x1002 => r.extend([0xff; 64]),
        0x1003 => r.extend([0xff; 8]),
        0x1009 => r.extend([0x55, 0x44, 0x33, 0x22, 0x11, 0x00]),
        0x2002 => r.extend([27, 0, 8]),
        0x2003 => r.extend(chip.le_features.to_le_bytes()),
        0x201c => r.extend([0xff; 8]),
        0x200f | 0x202a => r.push(8),
        0x202f => r.extend([251, 0, 0x48, 0x08, 251, 0, 0x48, 0x08]),
        0x203a => r.extend(1650u16.to_le_bytes()),
        0x203b => r.push(chip.adv_sets),
        0x2036 => r.push(0),
        0x2022 => r.extend([0x40, 0x00]),
        // Commands answered with Command Status.
        0x0406 | 0x200d | 0x2013 | 0x2016 | 0x2019 | 0x2032 | 0x2043 | 0x2044 => return None,
        _ => {}
    }
    Some(r)
}

async fn run(
    chip: Chip,
    mut io: DuplexStream,
    sent: Arc<Mutex<Vec<u16>>>,
    mut inject: mpsc::Receiver<Vec<u8>>,
) {
    loop {
        tokio::select! {
            b = io.read_u8() => {
                let Ok(ind) = b else { return };
                match ind {
                    0x01 => {
                        let mut h = [0u8; 3];
                        if io.read_exact(&mut h).await.is_err() { return }
                        let mut p = vec![0u8; usize::from(h[2])];
                        if io.read_exact(&mut p).await.is_err() { return }
                        let opcode = u16::from_le_bytes([h[0], h[1]]);
                        sent.lock().unwrap().push(opcode);
                        let ev = match reply(&chip, opcode) {
                            Some(ret) => {
                                let mut e = vec![0x04, 0x0e, (3 + ret.len()) as u8, 1, h[0], h[1]];
                                e.extend(ret);
                                e
                            }
                            None => vec![0x04, 0x0f, 4, 0, 1, h[0], h[1]],
                        };
                        if io.write_all(&ev).await.is_err() { return }
                    }
                    0x02 => {
                        let mut h = [0u8; 4];
                        if io.read_exact(&mut h).await.is_err() { return }
                        let mut p = vec![0u8; usize::from(u16::from_le_bytes([h[2], h[3]]))];
                        if io.read_exact(&mut p).await.is_err() { return }
                    }
                    _ => return,
                }
            }
            e = inject.recv() => {
                let Some(e) = e else { return };
                let mut f = vec![0x04];
                f.extend(e);
                if io.write_all(&f).await.is_err() { return }
            }
        }
    }
}

async fn start(chip: Chip) -> (Host, Controller) {
    let (host_side, chip_side) = tokio::io::duplex(1 << 16);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(run(chip, chip_side, sent.clone(), rx));
    let (r, w) = tokio::io::split(host_side);
    let host = Host::start(
        PacketReader::stream(r),
        PacketWriter::new(w),
        HostConfig::default(),
    )
    .await
    .unwrap();
    (host, Controller { sent, inject: tx })
}

/// An LE meta event.
fn le(sub: u8, body: &[u8]) -> Vec<u8> {
    let mut e = vec![0x3e, (1 + body.len()) as u8, sub];
    e.extend_from_slice(body);
    e
}

/// One LE Extended Advertising Report.
#[allow(clippy::too_many_arguments)]
fn ext_report(
    event_type: u16,
    addr: [u8; 6],
    sid: u8,
    tx: i8,
    rssi: i8,
    interval: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut b = vec![1u8];
    b.extend(event_type.to_le_bytes());
    b.push(1); // random address
    b.extend(addr);
    b.extend([1, 1, sid, tx as u8, rssi as u8]);
    b.extend(interval.to_le_bytes());
    b.push(0);
    b.extend([0u8; 6]);
    b.push(data.len() as u8);
    b.extend_from_slice(data);
    le(0x0d, &b)
}

/// One legacy LE Advertising Report.
fn legacy_report(event_type: u8, addr: [u8; 6], rssi: i8, data: &[u8]) -> Vec<u8> {
    let mut b = vec![1u8, event_type, 1];
    b.extend(addr);
    b.push(data.len() as u8);
    b.extend_from_slice(data);
    b.push(rssi as u8);
    le(0x02, &b)
}

async fn next_report(ev: &mut broadcast::Receiver<HostEvent>) -> Arc<bluetooth_host::Report> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ev.recv()).await {
            Ok(Ok(HostEvent::Advertisement(r))) => return r,
            Ok(Ok(_)) => {}
            other => panic!("no report: {other:?}"),
        }
    }
}

const ADDR: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0xf1];

#[tokio::test]
async fn reassembles_fragmented_extended_reports() {
    let (host, chip) = start(bt5()).await;
    let mut ev = host.events();
    host.start_scan(ScanConfig {
        dedup: Dedup::Off,
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    assert!(
        chip.opcodes().contains(&0x2041) && chip.opcodes().contains(&0x2042),
        "extended scan commands"
    );
    let a: Vec<u8> = (0..200u8).collect();
    let b: Vec<u8> = (200..=255u8).collect();
    // Data status 01 (more to come) on the first part, 00 on the last.
    chip.event(ext_report(0x0020, ADDR, 3, -8, -60, 0, &a))
        .await;
    chip.event(ext_report(0x0000, ADDR, 3, -8, -61, 0x0050, &b))
        .await;
    let r = next_report(&mut ev).await;
    let mut want = a.clone();
    want.extend(&b);
    assert_eq!(r.data, want);
    assert_eq!(
        (r.sid, r.legacy, r.tx_power, r.rssi, r.periodic_interval),
        (Some(3), false, Some(-8), -61, Some(0x50))
    );
    // Truncated: status 10.
    chip.event(ext_report(0x0040, ADDR, 4, 127, -70, 0, &[1, 2, 3]))
        .await;
    let r = next_report(&mut ev).await;
    assert!(r.truncated);
    assert_eq!(r.tx_power, None, "127 means not reported");
}

#[tokio::test]
async fn merges_legacy_scan_responses_in_extended_reports() {
    let (host, chip) = start(bt5()).await;
    let mut ev = host.events();
    host.start_scan(ScanConfig {
        active: true,
        dedup: Dedup::Off,
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    let adv = hex::decode("0201060403666f6f").unwrap();
    let rsp = hex::decode("020af4").unwrap();
    // ADV_IND with legacy PDUs (0x13), then its SCAN_RSP (0x1b).
    chip.event(ext_report(0x0013, ADDR, 0xff, 127, -50, 0, &adv))
        .await;
    let r = next_report(&mut ev).await;
    assert!(r.legacy && r.connectable && r.scannable && r.sid.is_none());
    assert_eq!(r.scan_response, None);
    chip.event(ext_report(0x001b, ADDR, 0xff, 127, -52, 0, &rsp))
        .await;
    let r = next_report(&mut ev).await;
    assert_eq!(r.data, adv, "the advertisement's data stays");
    assert_eq!(r.scan_response.as_deref(), Some(&rsp[..]));
    assert!(
        r.legacy && r.connectable,
        "the scan response keeps the advertisement's properties"
    );
    assert_eq!(r.advertisement().tx_power, Some(-12));
}

#[tokio::test]
async fn rejects_malformed_events() {
    // A malformed extended advertising report is dropped; scanning goes on.
    let (host, chip) = start(bt5()).await;
    let mut ev = host.events();
    host.start_scan(ScanConfig {
        dedup: Dedup::Off,
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    chip.event(hex::decode("3e0c0d6666010000000000000a03").unwrap())
        .await;
    chip.event(ext_report(0x0000, ADDR, 1, 127, -50, 0, &[2, 1, 6]))
        .await;
    assert_eq!(
        next_report(&mut ev).await.data,
        vec![2, 1, 6],
        "the host is still running"
    );
}

#[tokio::test]
async fn duplicate_filtering_by_change_and_interval() {
    let (host, chip) = start(bt5()).await;
    let mut ev = host.events();
    host.start_scan(ScanConfig {
        dedup: Dedup::Changes,
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    for _ in 0..5 {
        chip.event(ext_report(0x0000, ADDR, 1, 127, -50, 0, &[2, 1, 6]))
            .await;
    }
    chip.event(ext_report(0x0000, ADDR, 1, 127, -50, 0, &[2, 1, 4]))
        .await;
    assert_eq!(next_report(&mut ev).await.data, vec![2, 1, 6]);
    assert_eq!(
        next_report(&mut ev).await.data,
        vec![2, 1, 4],
        "only the change is reported"
    );
}

#[tokio::test]
async fn always_reported_ad_types_pass_duplicate_filtering() {
    let (host, chip) = start(bt5()).await;
    let mut ev = host.events();
    host.start_scan(ScanConfig {
        dedup: Dedup::Changes,
        always_report: vec![0x29],
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    // A PB-ADV PDU sent three times, identical, then a plain one twice.
    let pb_adv = [4, 0x29, 1, 2, 3];
    for _ in 0..3 {
        chip.event(ext_report(0x0000, ADDR, 1, 127, -50, 0, &pb_adv))
            .await;
    }
    for _ in 0..2 {
        chip.event(ext_report(0x0000, ADDR, 1, 127, -50, 0, &[2, 1, 6]))
            .await;
    }
    chip.event(ext_report(0x0000, ADDR, 1, 127, -50, 0, &[2, 1, 4]))
        .await;
    for _ in 0..3 {
        assert_eq!(next_report(&mut ev).await.data, pb_adv.to_vec());
    }
    assert_eq!(next_report(&mut ev).await.data, vec![2, 1, 6]);
    assert_eq!(
        next_report(&mut ev).await.data,
        vec![2, 1, 4],
        "the repeat is filtered"
    );
}

#[tokio::test]
async fn a_bluetooth_4_controller_degrades_cleanly() {
    let (host, chip) = start(pi3()).await;
    let caps = host.capabilities().clone();
    assert!(!caps.extended_advertising() && !caps.coded_phy() && !caps.data_length_extension());
    let mut ev = host.events();

    // Scanning uses the legacy commands, and legacy reports merge.
    host.start_scan(ScanConfig {
        active: true,
        dedup: Dedup::Off,
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    let ops = chip.opcodes();
    assert!(ops.contains(&0x200b) && ops.contains(&0x200c));
    assert!(
        !ops.iter().any(|o| (0x2036..=0x2046).contains(o)),
        "no extended commands: {ops:x?}"
    );
    chip.event(legacy_report(0x00, ADDR, -40, &[2, 1, 6])).await;
    chip.event(legacy_report(0x04, ADDR, -41, &[2, 0x0a, 0]))
        .await;
    next_report(&mut ev).await;
    let r = next_report(&mut ev).await;
    assert!(r.legacy && r.connectable);
    assert_eq!(r.scan_response.as_deref(), Some(&[2, 0x0a, 0][..]));

    // One legacy advertising set; anything more is refused, not attempted.
    let set = host
        .advertise(&AdvertisingParams::default(), &[2, 1, 6], &[])
        .await
        .unwrap();
    assert!(chip.opcodes().contains(&0x2006) && chip.opcodes().contains(&0x200a));
    assert!(matches!(
        host.advertise(&AdvertisingParams::default(), &[], &[])
            .await,
        Err(Error::Unsupported(_))
    ));
    let ext = AdvertisingParams {
        legacy: Some(false),
        ..AdvertisingParams::default()
    };
    host.stop_advertising(set).await.unwrap();
    assert!(matches!(
        host.advertise(&ext, &[], &[]).await,
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        host.advertise(&AdvertisingParams::default(), &[0; 40], &[])
            .await,
        Err(Error::InvalidParameter(_))
    ));
    assert!(matches!(
        host.sync_periodic("F1:22:33:44:55:66/random".parse().unwrap(), 0, 0, 1000)
            .await,
        Err(Error::Unsupported(_))
    ));

    // Connecting uses LE Create Connection; PHY and DLE are refused cleanly.
    let h = host.clone();
    let connecting = tokio::spawn(async move {
        h.connect(
            "F1:22:33:44:55:66/random".parse().unwrap(),
            &ConnectParams::default(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(chip.opcodes().contains(&0x200d));
    let mut cc = vec![0x00, 0x40, 0x00, 0x00, 0x01];
    cc.extend(ADDR);
    cc.extend([24, 0, 0, 0, 0x90, 0x01, 0]);
    chip.event(le(0x01, &cc)).await;
    let conn = connecting.await.unwrap().unwrap();
    assert_eq!(conn.handle(), 0x0040);
    assert_eq!(conn.params().interval, 24);
    assert!(matches!(
        conn.set_phy(&[Phy::Le2m], &[Phy::Le2m], false).await,
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        conn.set_data_length(251, 2120).await,
        Err(Error::Unsupported(_))
    ));
}

#[tokio::test]
async fn reports_a_hardware_error_and_stops() {
    let (host, chip) = start(bt5()).await;
    let mut ev = host.events();
    chip.event(vec![0x10, 0x01, 0x42]).await;
    let reason = tokio::time::timeout(Duration::from_secs(5), host.stopped())
        .await
        .unwrap();
    assert!(reason.contains("hardware error"), "{reason}");
    loop {
        if let Ok(HostEvent::Stopped(_)) = ev.recv().await {
            break;
        }
    }
    assert!(host.start_scan(ScanConfig::default()).await.is_err());
}

/// Resident memory, kB (Linux).
#[cfg(target_os = "linux")]
fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches(" kB").trim().parse().ok())
        .unwrap()
}

/// The budget: under 8 MB resident while scanning a busy site. Five
/// thousand advertisers, 200,000 reports, every one decoded as the bridge
/// would. Run in CI with `--ignored` (release build, Linux).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn busy_site_memory_budget() {
    let (host, chip) = start(bt5()).await;
    let mut ev = host.events();
    host.start_scan(ScanConfig {
        dedup: Dedup::IntervalMs(10_000),
        ..ScanConfig::default()
    })
    .await
    .unwrap();
    let drain = tokio::spawn(async move {
        let mut n = 0u64;
        while let Ok(e) = ev.recv().await {
            if let HostEvent::Advertisement(r) = e {
                let adv = r.advertisement();
                n += bluetooth_adv::beacon::decode(&adv, &Default::default()).len() as u64;
            }
        }
        n
    });
    for i in 0..200_000u32 {
        let d = i % 5000;
        let addr = [d as u8, (d >> 8) as u8, 0x33, 0x44, 0x55, 0xc1];
        let mut data =
            hex::decode("0201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000010002c5").unwrap();
        data[25] = (i % 7) as u8;
        chip.event(ext_report(0x0010, addr, 0xff, 127, -70, 0, &data))
            .await;
        if i % 1000 == 0 {
            tokio::task::yield_now().await;
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let rss = rss_kb();
    eprintln!("resident: {rss} kB");
    drop(host);
    drain.abort();
    assert!(rss < 8 * 1024, "{rss} kB resident, over the 8 MB budget");
}
