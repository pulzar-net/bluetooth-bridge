//! The network layer (Mesh Protocol 3.4): Network PDUs encrypted and
//! obfuscated with a network key's material, decoded by trying the keys
//! whose NID matches, and a bounded message cache so a relayed copy is
//! handled once.

use std::collections::{HashSet, VecDeque};

use crate::crypto::{self, Key, NetworkMaterial};

/// A network key and what is derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkKey {
    /// The global key index.
    pub index: u16,
    /// The key.
    pub key: Key,
    /// NID, encryption key and privacy key (k2, master credentials).
    pub material: NetworkMaterial,
    /// The Network ID (k3).
    pub network_id: [u8; 8],
    /// The beacon key, for secure network beacons.
    pub beacon_key: Key,
    /// The identity key, for node identity advertising.
    pub identity_key: Key,
}

impl NetworkKey {
    /// Derives everything from the key.
    pub fn new(index: u16, key: Key) -> Self {
        NetworkKey {
            index,
            key,
            material: crypto::k2(&key, &[0]),
            network_id: crypto::k3(&key),
            beacon_key: crypto::beacon_key(&key),
            identity_key: crypto::identity_key(&key),
        }
    }
}

/// A Network PDU, decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPdu {
    /// Control message (true) or access message.
    pub ctl: bool,
    /// Time to live.
    pub ttl: u8,
    /// Sequence number (24 bits).
    pub seq: u32,
    /// Source address (a unicast address).
    pub src: u16,
    /// Destination address.
    pub dst: u16,
    /// The lower transport PDU.
    pub transport: Vec<u8>,
}

/// The most a Network PDU carries on the advertising bearer.
pub const MAX_PDU: usize = 29;

fn nonce(pdu: &NetworkPdu, iv_index: u32) -> [u8; 13] {
    let mut n = [0u8; 13];
    n[1] = (u8::from(pdu.ctl) << 7) | (pdu.ttl & 0x7f);
    n[2..5].copy_from_slice(&pdu.seq.to_be_bytes()[1..]);
    n[5..7].copy_from_slice(&pdu.src.to_be_bytes());
    n[9..13].copy_from_slice(&iv_index.to_be_bytes());
    n
}

fn pecb(privacy_key: &Key, iv_index: u32, privacy_random: &[u8]) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[5..9].copy_from_slice(&iv_index.to_be_bytes());
    p[9..16].copy_from_slice(&privacy_random[..7]);
    crypto::e(privacy_key, &p)
}

/// Errors building a PDU.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The transport PDU does not fit.
    #[error("the transport PDU is {0} octets, more than a Network PDU carries")]
    TooLong(usize),
    /// A field is out of range.
    #[error("{0}")]
    Invalid(&'static str),
}

/// Encrypts and obfuscates a Network PDU.
pub fn encode(net: &NetworkKey, iv_index: u32, pdu: &NetworkPdu) -> Result<Vec<u8>, Error> {
    let mic = if pdu.ctl { 8 } else { 4 };
    if 9 + pdu.transport.len() + mic > MAX_PDU {
        return Err(Error::TooLong(pdu.transport.len()));
    }
    if pdu.seq > 0x00ff_ffff || pdu.ttl > 127 || pdu.src == 0 || pdu.src & 0x8000 != 0 {
        return Err(Error::Invalid("seq, ttl or source address out of range"));
    }
    let mut plain = pdu.dst.to_be_bytes().to_vec();
    plain.extend_from_slice(&pdu.transport);
    let enc = crypto::ccm_encrypt(
        &net.material.encryption_key,
        &nonce(pdu, iv_index),
        &[],
        &plain,
        mic,
    );
    let p = pecb(&net.material.privacy_key, iv_index, &enc);
    let mut header = [0u8; 6];
    header[0] = (u8::from(pdu.ctl) << 7) | (pdu.ttl & 0x7f);
    header[1..4].copy_from_slice(&pdu.seq.to_be_bytes()[1..]);
    header[4..6].copy_from_slice(&pdu.src.to_be_bytes());
    let mut out = Vec::with_capacity(7 + enc.len());
    out.push((((iv_index & 1) as u8) << 7) | net.material.nid);
    out.extend(header.iter().zip(p.iter()).map(|(a, b)| a ^ b));
    out.extend_from_slice(&enc);
    Ok(out)
}

/// Decodes a Network PDU with whichever key opens it. `iv_index` is the
/// current one; a PDU whose IVI bit differs is tried with the one before
/// (during an IV update). Returns the key's position, the IV index used and
/// the PDU.
pub fn decode(keys: &[NetworkKey], iv_index: u32, data: &[u8]) -> Option<(usize, u32, NetworkPdu)> {
    if data.len() < 14 || data.len() > MAX_PDU {
        return None;
    }
    let ivi = data[0] >> 7;
    let nid = data[0] & 0x7f;
    let iv = if (iv_index & 1) as u8 == ivi {
        iv_index
    } else {
        iv_index.checked_sub(1)?
    };
    for (i, net) in keys
        .iter()
        .enumerate()
        .filter(|(_, k)| k.material.nid == nid)
    {
        let p = pecb(&net.material.privacy_key, iv, &data[7..]);
        let mut h = [0u8; 6];
        for (j, b) in h.iter_mut().enumerate() {
            *b = data[1 + j] ^ p[j];
        }
        let ctl = h[0] & 0x80 != 0;
        let mic = if ctl { 8 } else { 4 };
        if data.len() < 7 + 2 + mic + 1 {
            continue;
        }
        let pdu = NetworkPdu {
            ctl,
            ttl: h[0] & 0x7f,
            seq: u32::from_be_bytes([0, h[1], h[2], h[3]]),
            src: u16::from_be_bytes([h[4], h[5]]),
            dst: 0,
            transport: Vec::new(),
        };
        if let Some(plain) = crypto::ccm_decrypt(
            &net.material.encryption_key,
            &nonce(&pdu, iv),
            &[],
            &data[7..],
            mic,
        ) {
            if plain.len() < 2 {
                continue;
            }
            return Some((
                i,
                iv,
                NetworkPdu {
                    dst: u16::from_be_bytes([plain[0], plain[1]]),
                    transport: plain[2..].to_vec(),
                    ..pdu
                },
            ));
        }
    }
    None
}

/// Recently seen Network PDUs (by source and sequence), bounded.
pub struct Cache {
    seen: HashSet<(u16, u32)>,
    order: VecDeque<(u16, u32)>,
    limit: usize,
}

impl Cache {
    /// A cache of `limit` entries.
    pub fn new(limit: usize) -> Self {
        Cache {
            seen: HashSet::new(),
            order: VecDeque::new(),
            limit: limit.max(1),
        }
    }

    /// Whether this PDU is new; remembers it.
    pub fn insert(&mut self, src: u16, seq: u32) -> bool {
        if !self.seen.insert((src, seq)) {
            return false;
        }
        self.order.push_back((src, seq));
        if self.order.len() > self.limit {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    /// Mesh Protocol, 8.3.1 (Message #1: a control message, relayed by no one).
    #[test]
    fn message_1_sample() {
        let net = NetworkKey::new(0, h("7dd7364cd842ad18c17c2b820c84c3d6").try_into().unwrap());
        assert_eq!(net.material.nid, 0x68);
        assert_eq!(
            net.material.encryption_key.to_vec(),
            h("0953fa93e7caac9638f58820220a398e")
        );
        assert_eq!(
            net.material.privacy_key.to_vec(),
            h("8b84eedec100067d670971dd2aa700cf")
        );
        let pdu = NetworkPdu {
            ctl: true,
            ttl: 0,
            seq: 1,
            src: 0x1201,
            dst: 0xfffd,
            transport: h("034b50057e400000010000"),
        };
        let wire = encode(&net, 0x1234_5678, &pdu).unwrap();
        assert_eq!(
            hex::encode(&wire),
            "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df"
        );
        let (i, iv, back) = decode(std::slice::from_ref(&net), 0x1234_5678, &wire).unwrap();
        assert_eq!((i, iv), (0, 0x1234_5678));
        assert_eq!(back, pdu);
    }

    #[test]
    fn access_round_trip_iv_update_and_tamper() {
        let net = NetworkKey::new(1, [9; 16]);
        let pdu = NetworkPdu {
            ctl: false,
            ttl: 5,
            seq: 0x00ab_cdef,
            src: 0x0042,
            dst: 0xc000,
            transport: vec![0x66; 16],
        };
        let wire = encode(&net, 7, &pdu).unwrap();
        assert_eq!(wire.len(), 29);
        // The receiver moved on to IV index 8: IVI 1 still opens with 7.
        let (_, iv, back) = decode(std::slice::from_ref(&net), 8, &wire).unwrap();
        assert_eq!((iv, back), (7, pdu.clone()));
        let mut bad = wire.clone();
        bad[20] ^= 1;
        assert!(decode(std::slice::from_ref(&net), 7, &bad).is_none());
        assert!(decode(std::slice::from_ref(&net), 7, &wire[..10]).is_none());
        assert!(encode(
            &net,
            7,
            &NetworkPdu {
                transport: vec![0; 17],
                ..pdu
            }
        )
        .is_err());
    }

    #[test]
    fn cache_is_bounded() {
        let mut c = Cache::new(2);
        assert!(c.insert(1, 1));
        assert!(!c.insert(1, 1));
        assert!(c.insert(1, 2));
        assert!(c.insert(1, 3));
        assert!(c.insert(1, 1), "the oldest was forgotten");
    }
}
