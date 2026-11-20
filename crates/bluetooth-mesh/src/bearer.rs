//! What Mesh puts on the advertising and GATT bearers: beacons (AD type
//! Mesh Beacon), PB-ADV (AD type PB-ADV: links and provisioning
//! transactions), and Proxy PDUs on the Mesh Proxy and Provisioning GATT
//! services.

use crate::crypto::{self, Key};

/// The FCS of 3GPP TS 27.010 (as in RFCOMM): CRC-8 with polynomial
/// x^8 + x^2 + x + 1, reflected, initial 0xFF, ones' complemented.
pub fn fcs(data: &[u8]) -> u8 {
    const CRC: crc::Crc<u8> = crc::Crc::<u8>::new(&crc::CRC_8_ROHC);
    0xff ^ CRC.checksum(data)
}

/// A Mesh beacon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Beacon {
    /// A device waiting to be provisioned.
    Unprovisioned {
        /// Its Device UUID.
        uuid: [u8; 16],
        /// OOB information (where its OOB data is).
        oob_info: u16,
        /// Hash of its URI, when it advertises one.
        uri_hash: Option<[u8; 4]>,
    },
    /// A network's key refresh and IV index state.
    SecureNetwork {
        /// Key refresh (bit 0), IV update (bit 1).
        flags: u8,
        /// The network's ID (k3 of its key).
        network_id: [u8; 8],
        /// IV index.
        iv_index: u32,
        /// Authentication value.
        auth: [u8; 8],
    },
}

impl Beacon {
    /// Parses a Mesh Beacon AD structure's data.
    pub fn parse(d: &[u8]) -> Option<Beacon> {
        match (d.first()?, d.len()) {
            (0x00, 19) | (0x00, 23) => Some(Beacon::Unprovisioned {
                uuid: d[1..17].try_into().ok()?,
                oob_info: u16::from_be_bytes([d[17], d[18]]),
                uri_hash: (d.len() == 23).then(|| [d[19], d[20], d[21], d[22]]),
            }),
            (0x01, 22) => Some(Beacon::SecureNetwork {
                flags: d[1],
                network_id: d[2..10].try_into().ok()?,
                iv_index: u32::from_be_bytes([d[10], d[11], d[12], d[13]]),
                auth: d[14..22].try_into().ok()?,
            }),
            _ => None,
        }
    }

    /// A secure network beacon for a network key, authenticated.
    pub fn secure_network(
        beacon_key: &Key,
        network_id: [u8; 8],
        flags: u8,
        iv_index: u32,
    ) -> Vec<u8> {
        let mut b = vec![0x01, flags];
        b.extend_from_slice(&network_id);
        b.extend_from_slice(&iv_index.to_be_bytes());
        let a = crypto::cmac(beacon_key, &b[1..]);
        b.extend_from_slice(&a[..8]);
        b
    }

    /// Whether a secure network beacon was made with `beacon_key`.
    pub fn authenticates(&self, beacon_key: &Key) -> bool {
        match self {
            Beacon::SecureNetwork {
                flags,
                network_id,
                iv_index,
                auth,
            } => {
                let mut m = vec![*flags];
                m.extend_from_slice(network_id);
                m.extend_from_slice(&iv_index.to_be_bytes());
                crypto::cmac(beacon_key, &m)[..8] == auth[..]
            }
            Beacon::Unprovisioned { .. } => false,
        }
    }
}

/// A Generic Provisioning PDU, as carried in PB-ADV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Generic {
    /// The first segment of a provisioning PDU.
    Start {
        /// The last segment's index.
        seg_n: u8,
        /// The whole PDU's length.
        total: u16,
        /// FCS of the whole PDU.
        fcs: u8,
        /// The first segment's data.
        data: Vec<u8>,
    },
    /// The transaction was received whole.
    Ack,
    /// A later segment.
    Continuation {
        /// Its index.
        index: u8,
        /// Its data.
        data: Vec<u8>,
    },
    /// Link Open, with the device's UUID.
    LinkOpen([u8; 16]),
    /// Link Ack.
    LinkAck,
    /// Link Close, with the reason (0 success, 1 timeout, 2 fail).
    LinkClose(u8),
}

/// One PB-ADV PDU: link, transaction number and Generic Provisioning PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbAdv {
    /// Link ID.
    pub link: u32,
    /// Transaction number.
    pub transaction: u8,
    /// The Generic Provisioning PDU.
    pub pdu: Generic,
}

/// Data in a Transaction Start on PB-ADV.
const START_DATA: usize = 20;
/// Data in a Transaction Continuation on PB-ADV.
const CONTINUATION_DATA: usize = 23;

impl PbAdv {
    /// Parses a PB-ADV AD structure's data.
    pub fn parse(d: &[u8]) -> Option<PbAdv> {
        if d.len() < 6 {
            return None;
        }
        let link = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
        let transaction = d[4];
        let g = &d[5..];
        let pdu = match g[0] & 0b11 {
            0b00 => {
                if g.len() < 5 {
                    return None;
                }
                Generic::Start {
                    seg_n: g[0] >> 2,
                    total: u16::from_be_bytes([g[1], g[2]]),
                    fcs: g[3],
                    data: g[4..].to_vec(),
                }
            }
            0b01 => Generic::Ack,
            0b10 => Generic::Continuation {
                index: g[0] >> 2,
                data: g[1..].to_vec(),
            },
            _ => match (g[0] >> 2, g.len()) {
                (0x00, 17) => Generic::LinkOpen(g[1..17].try_into().ok()?),
                (0x01, 1) => Generic::LinkAck,
                (0x02, 2) => Generic::LinkClose(g[1]),
                _ => return None,
            },
        };
        Some(PbAdv {
            link,
            transaction,
            pdu,
        })
    }

    /// The AD structure data.
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = self.link.to_be_bytes().to_vec();
        b.push(self.transaction);
        match &self.pdu {
            Generic::Start {
                seg_n,
                total,
                fcs,
                data,
            } => {
                b.push(seg_n << 2);
                b.extend_from_slice(&total.to_be_bytes());
                b.push(*fcs);
                b.extend_from_slice(data);
            }
            Generic::Ack => b.push(0x01),
            Generic::Continuation { index, data } => {
                b.push((index << 2) | 0b10);
                b.extend_from_slice(data);
            }
            Generic::LinkOpen(uuid) => {
                b.push(0x03);
                b.extend_from_slice(uuid);
            }
            Generic::LinkAck => b.push((0x01 << 2) | 0b11),
            Generic::LinkClose(r) => {
                b.push((0x02 << 2) | 0b11);
                b.push(*r);
            }
        }
        b
    }

    /// A provisioning PDU as the segments of one transaction.
    pub fn transaction(link: u32, transaction: u8, pdu: &[u8]) -> Vec<PbAdv> {
        let first = &pdu[..pdu.len().min(START_DATA)];
        let rest = pdu.get(START_DATA..).unwrap_or(&[]);
        let conts: Vec<&[u8]> = rest.chunks(CONTINUATION_DATA).collect();
        let mut out = vec![PbAdv {
            link,
            transaction,
            pdu: Generic::Start {
                seg_n: conts.len() as u8,
                total: pdu.len() as u16,
                fcs: fcs(pdu),
                data: first.to_vec(),
            },
        }];
        out.extend(conts.into_iter().enumerate().map(|(i, c)| PbAdv {
            link,
            transaction,
            pdu: Generic::Continuation {
                index: (i + 1) as u8,
                data: c.to_vec(),
            },
        }));
        out
    }
}

/// A transaction being received: (number, last segment, total, FCS, segments).
type Partial = (u8, u8, u16, u8, Vec<Option<Vec<u8>>>);

/// Reassembles one PB-ADV transaction.
#[derive(Default)]
pub struct TransactionRx {
    current: Option<Partial>,
}

impl TransactionRx {
    /// Adds a segment; the whole provisioning PDU once complete and its FCS checks.
    pub fn add(&mut self, p: &PbAdv) -> Option<Vec<u8>> {
        match &p.pdu {
            Generic::Start {
                seg_n,
                total,
                fcs: f,
                data,
            } => {
                if *seg_n > 63 {
                    return None;
                }
                let mut parts = vec![None; usize::from(*seg_n) + 1];
                parts[0] = Some(data.clone());
                self.current = Some((p.transaction, *seg_n, *total, *f, parts));
            }
            Generic::Continuation { index, data } => {
                let (t, n, ..) = self.current.as_mut()?;
                if *t != p.transaction || index > n {
                    return None;
                }
                self.current.as_mut()?.4[usize::from(*index)] = Some(data.clone());
            }
            _ => return None,
        }
        let (_, _, total, f, parts) = self.current.as_ref()?;
        if !parts.iter().all(Option::is_some) {
            return None;
        }
        let pdu: Vec<u8> = parts.iter().flatten().flatten().copied().collect();
        let ok = pdu.len() == usize::from(*total) && fcs(&pdu) == *f;
        self.current = None;
        ok.then_some(pdu)
    }
}

/// Proxy PDU message types.
pub mod proxy {
    /// A Network PDU.
    pub const NETWORK: u8 = 0x00;
    /// A Mesh Beacon.
    pub const BEACON: u8 = 0x01;
    /// Proxy Configuration.
    pub const CONFIGURATION: u8 = 0x02;
    /// A Provisioning PDU.
    pub const PROVISIONING: u8 = 0x03;
}

/// Splits a message into Proxy PDUs for an ATT MTU (each write carries MTU - 3).
pub fn proxy_segments(kind: u8, msg: &[u8], mtu: u16) -> Vec<Vec<u8>> {
    let room = usize::from(mtu.saturating_sub(3)).max(20) - 1;
    if msg.len() <= room {
        let mut p = vec![kind & 0x3f];
        p.extend_from_slice(msg);
        return vec![p];
    }
    let chunks: Vec<&[u8]> = msg.chunks(room).collect();
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let sar = match i {
                0 => 0b01,
                i if i == last => 0b11,
                _ => 0b10,
            };
            let mut p = vec![(sar << 6) | (kind & 0x3f)];
            p.extend_from_slice(c);
            p
        })
        .collect()
}

/// Reassembles Proxy PDUs into (type, message).
#[derive(Default)]
pub struct ProxyRx {
    partial: Option<(u8, Vec<u8>)>,
}

/// The largest proxy message reassembled (a provisioning PDU or network PDU is far smaller).
const MAX_PROXY: usize = 512;

impl ProxyRx {
    /// Adds one Proxy PDU; a whole message when complete.
    pub fn add(&mut self, p: &[u8]) -> Option<(u8, Vec<u8>)> {
        let (&h, data) = p.split_first()?;
        let (sar, kind) = (h >> 6, h & 0x3f);
        match sar {
            0b00 => {
                self.partial = None;
                Some((kind, data.to_vec()))
            }
            0b01 => {
                self.partial = Some((kind, data.to_vec()));
                None
            }
            _ => {
                let (k, buf) = self.partial.as_mut()?;
                if *k != kind || buf.len() + data.len() > MAX_PROXY {
                    self.partial = None;
                    return None;
                }
                buf.extend_from_slice(data);
                if sar == 0b11 {
                    self.partial.take()
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fcs_matches_rfcomm() {
        // RFCOMM SABM on DLCI 0: address 0x03, control 0x3f, length 0x01;
        // the FCS of a SABM covers all three, and is 0x1c.
        assert_eq!(fcs(&[0x03, 0x3f, 0x01]), 0x1c);
    }

    #[test]
    fn beacons_parse_and_authenticate() {
        let k = crypto::beacon_key(&[0x11; 16]);
        let b = Beacon::secure_network(&k, [1, 2, 3, 4, 5, 6, 7, 8], 0x02, 0x12345678);
        let parsed = Beacon::parse(&b).unwrap();
        assert!(parsed.authenticates(&k));
        assert!(!parsed.authenticates(&[0; 16]));
        let mut u = vec![0x00];
        u.extend([0xaa; 16]);
        u.extend([0x40, 0x00]);
        assert!(matches!(
            Beacon::parse(&u),
            Some(Beacon::Unprovisioned {
                oob_info: 0x4000,
                uri_hash: None,
                ..
            })
        ));
        assert!(Beacon::parse(&[0x01, 0]).is_none());
    }

    #[test]
    fn pb_adv_transactions_round_trip() {
        let pdu: Vec<u8> = (0..65u8).collect(); // a Public Key PDU's size
        let segs = PbAdv::transaction(0xdeadbeef, 0x80, &pdu);
        assert_eq!(segs.len(), 3); // 20 + 23 + 22 octets
        let mut rx = TransactionRx::default();
        let mut whole = None;
        // Continuations out of order after their start.
        for s in segs.iter().take(1).chain(segs.iter().skip(1).rev()) {
            let back = PbAdv::parse(&s.bytes()).unwrap();
            assert_eq!(&back, s);
            if let Some(p) = rx.add(&back) {
                whole = Some(p);
            }
        }
        assert_eq!(whole, Some(pdu.clone()));
        let mut bad = PbAdv::transaction(1, 0, &pdu);
        if let Generic::Start { fcs, .. } = &mut bad[0].pdu {
            *fcs ^= 1;
        }
        let mut rx = TransactionRx::default();
        assert!(
            bad.iter().filter_map(|s| rx.add(s)).next().is_none(),
            "a bad FCS is dropped"
        );
        for g in [
            Generic::LinkOpen([7; 16]),
            Generic::LinkAck,
            Generic::LinkClose(1),
            Generic::Ack,
        ] {
            let p = PbAdv {
                link: 9,
                transaction: 0,
                pdu: g,
            };
            assert_eq!(PbAdv::parse(&p.bytes()), Some(p));
        }
    }

    #[test]
    fn proxy_sar_round_trip() {
        let msg: Vec<u8> = (0..100u8).collect();
        let mut rx = ProxyRx::default();
        let out: Vec<_> = proxy_segments(proxy::PROVISIONING, &msg, 23)
            .iter()
            .filter_map(|p| rx.add(p))
            .collect();
        assert_eq!(out, vec![(proxy::PROVISIONING, msg)]);
        assert_eq!(rx.add(&[0x00, 1, 2]), Some((proxy::NETWORK, vec![1, 2])));
        assert_eq!(
            rx.add(&[0x80, 1]),
            None,
            "a continuation without a start is dropped"
        );
    }
}
