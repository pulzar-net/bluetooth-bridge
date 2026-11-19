//! Entry points for the fuzz targets (`fuzz/`): every parser that reads
//! bytes from the air or the controller, without a running host. Built only
//! with the `fuzzing` feature.

use crate::connection::Security;
use crate::gatt::server::{Access, CharacteristicDef, Database, ServiceDef};

/// Splits `data` into H4 frames by their headers, as a stream would.
pub fn h4(data: &[u8]) {
    let _ = crate::transport::Packet::from_h4(data);
}

/// Parses an HCI event as the host does, walking advertising reports.
pub fn hci_event(data: &[u8]) {
    use bt_hci::event::le::LeEvent;
    use bt_hci::event::Event;
    use bt_hci::FromHciBytes;
    if !crate::host::parsable(data) {
        return;
    }
    if let Ok((e, _)) = Event::from_hci_bytes(data) {
        match e {
            Event::Le(LeEvent::LeAdvertisingReport(r)) => {
                for r in r.reports.iter().flatten() {
                    let _ = bluetooth_adv::Advertisement::parse(r.data);
                }
            }
            Event::Le(LeEvent::LeExtendedAdvertisingReport(r)) => {
                for r in r.reports.iter().flatten() {
                    let _ = bluetooth_adv::Advertisement::parse(r.data);
                }
            }
            Event::NumberOfCompletedPackets(e) => {
                for c in e.completed_packets {
                    let _ = (c.handle(), c.num_completed_packets());
                }
            }
            _ => {}
        }
    }
}

/// Feeds ACL packets (each prefixed by a one-byte length) to reassembly.
pub fn acl(mut data: &[u8]) {
    let mut r = crate::hci::Reassembly::default();
    while let Some((&n, rest)) = data.split_first() {
        let n = usize::from(n).min(rest.len());
        let _ = r.push(&rest[..n]);
        data = &rest[n..];
    }
}

/// Runs ATT requests (each prefixed by a one-byte length) against a GATT
/// server, the first byte choosing the link's security and MTU.
pub fn att_server(data: &[u8]) {
    let Some((&mode, mut rest)) = data.split_first() else {
        return;
    };
    let db = Database::new("fuzz", 0);
    let _ = db.add(&ServiceDef {
        uuid: bluetooth_adv::Uuid::Uuid16(0xfff0),
        primary: true,
        characteristics: vec![
            CharacteristicDef {
                uuid: bluetooth_adv::Uuid::Uuid16(0xfff1),
                properties: vec![
                    "read".into(),
                    "write".into(),
                    "notify".into(),
                    "indicate".into(),
                ],
                read: Access::Open,
                write: Access::Encrypted,
                value: vec![1, 2, 3],
                max_len: 64,
                description: Some("x".into()),
                descriptors: vec![],
            },
            CharacteristicDef {
                uuid: bluetooth_adv::Uuid::parse("12345678-1234-5678-1234-56789abcdef0")
                    .unwrap_or(bluetooth_adv::Uuid::Uuid16(0xfff2)),
                properties: vec!["read".into(), "write_without_response".into()],
                read: Access::Authenticated,
                write: Access::Open,
                value: vec![0; 300],
                max_len: 512,
                description: None,
                descriptors: vec![],
            },
        ],
    });
    let sec = Security {
        encrypted: mode & 1 != 0,
        authenticated: mode & 2 != 0,
        secure_connections: mode & 4 != 0,
        key_size: if mode & 8 != 0 { 16 } else { 7 },
        bonded: false,
    };
    let mtu = 23 + usize::from(mode >> 4) * 33;
    while let Some((&n, r)) = rest.split_first() {
        let n = usize::from(n).min(r.len());
        if n > 0 {
            let _ = db.handle_fuzz(u16::from(mode & 3), &sec, mtu, &r[..n]);
        }
        rest = &r[n..];
    }
}

/// Parses a Pairing Request or Response.
pub fn smp_features(data: &[u8]) {
    let _ = crate::smp::parse_features(data);
}
