//! The upper and lower transport layers (Mesh Protocol 3.5, 3.6).
//!
//! Upper: an access payload encrypted with an application key (AKF 1, its
//! AID in the header) or the device key (AKF 0), TransMIC 32 or 64 bits.
//! Lower: one unsegmented PDU, or up to 32 segments of 12 octets each,
//! acknowledged by Segment Acknowledgment messages; [`Reassembly`] collects
//! segments on the receiving side and says what to acknowledge.

use std::collections::HashMap;

use crate::crypto::{self, Key};

/// Which key secures an access message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKey<'a> {
    /// An application key and its AID (k4).
    App(&'a Key, u8),
    /// The device key of the source or destination.
    Device(&'a Key),
}

/// An application or device nonce.
fn nonce(device: bool, szmic: bool, seq: u32, src: u16, dst: u16, iv_index: u32) -> [u8; 13] {
    let mut n = [0u8; 13];
    n[0] = if device { 0x02 } else { 0x01 };
    n[1] = u8::from(szmic) << 7;
    n[2..5].copy_from_slice(&seq.to_be_bytes()[1..]);
    n[5..7].copy_from_slice(&src.to_be_bytes());
    n[7..9].copy_from_slice(&dst.to_be_bytes());
    n[9..13].copy_from_slice(&iv_index.to_be_bytes());
    n
}

/// Addressing and sequence of an access message, for its nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// Sequence number of the first segment (SeqAuth's low 24 bits).
    pub seq: u32,
    /// Source.
    pub src: u16,
    /// Destination.
    pub dst: u16,
    /// IV index.
    pub iv_index: u32,
    /// A virtual destination's Label UUID (the additional data).
    pub label: Option<[u8; 16]>,
}

/// Encrypts an access payload; `big_mic` chooses the 64-bit TransMIC
/// (segmented messages only).
pub fn encrypt_access(key: AccessKey<'_>, m: &Meta, payload: &[u8], big_mic: bool) -> Vec<u8> {
    let (k, device) = match key {
        AccessKey::App(k, _) => (k, false),
        AccessKey::Device(k) => (k, true),
    };
    let aad = m.label.as_ref().map(|l| &l[..]).unwrap_or(&[]);
    crypto::ccm_encrypt(
        k,
        &nonce(device, big_mic, m.seq, m.src, m.dst, m.iv_index),
        aad,
        payload,
        if big_mic { 8 } else { 4 },
    )
}

/// Decrypts an upper transport access PDU.
pub fn decrypt_access(
    key: AccessKey<'_>,
    m: &Meta,
    sealed: &[u8],
    big_mic: bool,
) -> Option<Vec<u8>> {
    let (k, device) = match key {
        AccessKey::App(k, _) => (k, false),
        AccessKey::Device(k) => (k, true),
    };
    let aad = m.label.as_ref().map(|l| &l[..]).unwrap_or(&[]);
    crypto::ccm_decrypt(
        k,
        &nonce(device, big_mic, m.seq, m.src, m.dst, m.iv_index),
        aad,
        sealed,
        if big_mic { 8 } else { 4 },
    )
}

/// The largest upper transport PDU unsegmented: 15 octets (access).
pub const MAX_UNSEGMENTED_ACCESS: usize = 15;
/// Octets of upper transport PDU per access segment.
pub const SEGMENT_SIZE: usize = 12;
/// The most segments a message may have.
pub const MAX_SEGMENTS: usize = 32;

/// Lower transport PDUs for an encrypted access message. `akf_aid` is
/// `None` for the device key, `Some(aid)` for an application key. Each
/// returned PDU goes in its own Network PDU with sequence numbers
/// `seq_zero`'s message's first and onward.
pub fn segment_access(
    akf_aid: Option<u8>,
    big_mic: bool,
    seq_zero: u32,
    upper: &[u8],
    force_segmented: bool,
) -> Option<Vec<Vec<u8>>> {
    let header = match akf_aid {
        Some(aid) => 0x40 | (aid & 0x3f),
        None => 0x00,
    };
    if !force_segmented && !big_mic && upper.len() <= MAX_UNSEGMENTED_ACCESS {
        let mut p = vec![header];
        p.extend_from_slice(upper);
        return Some(vec![p]);
    }
    let n = upper.len().div_ceil(SEGMENT_SIZE).max(1);
    if n > MAX_SEGMENTS {
        return None;
    }
    let seq_zero = (seq_zero & 0x1fff) as u16;
    Some(
        upper
            .chunks(SEGMENT_SIZE)
            .enumerate()
            .map(|(o, c)| {
                let (o, last) = (o as u32, (n - 1) as u32);
                let bits: u32 =
                    (u32::from(big_mic) << 23) | (u32::from(seq_zero) << 10) | (o << 5) | last;
                let mut p = vec![0x80 | header];
                p.extend_from_slice(&bits.to_be_bytes()[1..]);
                p.extend_from_slice(c);
                p
            })
            .collect(),
    )
}

/// A parsed lower transport PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lower {
    /// An unsegmented access message: AKF/AID and the upper transport PDU.
    Access {
        /// `Some(aid)` for an application key, `None` for the device key.
        aid: Option<u8>,
        /// The upper transport PDU.
        upper: Vec<u8>,
    },
    /// One segment of an access message.
    Segment {
        /// `Some(aid)` or `None` (device key).
        aid: Option<u8>,
        /// 64-bit TransMIC.
        big_mic: bool,
        /// SeqZero (13 bits).
        seq_zero: u16,
        /// This segment's number.
        seg_o: u8,
        /// The last segment's number.
        seg_n: u8,
        /// The segment's octets.
        data: Vec<u8>,
    },
    /// An unsegmented control message: opcode and parameters.
    Control {
        /// The opcode (7 bits).
        opcode: u8,
        /// Its parameters.
        params: Vec<u8>,
    },
    /// A Segment Acknowledgment.
    Ack {
        /// Sent by a Friend on behalf of a Low Power node.
        obo: bool,
        /// SeqZero of the acknowledged message.
        seq_zero: u16,
        /// Bit `n` set: segment `n` received.
        block: u32,
    },
}

/// Parses a lower transport PDU (`ctl` from the network header).
pub fn parse(ctl: bool, p: &[u8]) -> Option<Lower> {
    let (&h, rest) = p.split_first()?;
    let seg = h & 0x80 != 0;
    match (ctl, seg) {
        (false, false) => Some(Lower::Access {
            aid: (h & 0x40 != 0).then_some(h & 0x3f),
            upper: rest.to_vec(),
        }),
        (false, true) => {
            if rest.len() < 4 {
                return None;
            }
            let bits = u32::from_be_bytes([0, rest[0], rest[1], rest[2]]);
            let (seg_o, seg_n) = (((bits >> 5) & 0x1f) as u8, (bits & 0x1f) as u8);
            if seg_o > seg_n {
                return None;
            }
            Some(Lower::Segment {
                aid: (h & 0x40 != 0).then_some(h & 0x3f),
                big_mic: bits & 0x80_0000 != 0,
                seq_zero: ((bits >> 10) & 0x1fff) as u16,
                seg_o,
                seg_n,
                data: rest[3..].to_vec(),
            })
        }
        (true, false) if h & 0x7f == 0 => {
            if rest.len() != 6 {
                return None;
            }
            let v = u16::from_be_bytes([rest[0], rest[1]]);
            Some(Lower::Ack {
                obo: v & 0x8000 != 0,
                seq_zero: (v >> 2) & 0x1fff,
                block: u32::from_be_bytes([rest[2], rest[3], rest[4], rest[5]]),
            })
        }
        (true, false) => Some(Lower::Control {
            opcode: h & 0x7f,
            params: rest.to_vec(),
        }),
        // Segmented control messages are reassembled like access ones; not needed yet.
        (true, true) => None,
    }
}

/// A Segment Acknowledgment PDU.
pub fn ack(seq_zero: u16, block: u32) -> Vec<u8> {
    let v = (seq_zero & 0x1fff) << 2;
    let mut p = vec![0x00];
    p.extend_from_slice(&v.to_be_bytes());
    p.extend_from_slice(&block.to_be_bytes());
    p
}

/// What reassembly produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reassembled {
    /// More to come; acknowledge `block` so far.
    Partial {
        /// Segments received.
        block: u32,
    },
    /// Complete: the upper transport PDU, and the block to acknowledge.
    Complete {
        /// `Some(aid)` or `None` (device key).
        aid: Option<u8>,
        /// 64-bit TransMIC.
        big_mic: bool,
        /// The upper transport PDU.
        upper: Vec<u8>,
        /// All segments, for the final acknowledgment.
        block: u32,
    },
}

struct Incoming {
    seq_zero: u16,
    aid: Option<u8>,
    big_mic: bool,
    seg_n: u8,
    parts: Vec<Option<Vec<u8>>>,
}

/// Segments being reassembled, per source. One message per source at a
/// time, as the specification requires; a newer SeqZero replaces an older.
#[derive(Default)]
pub struct Reassembly {
    incoming: HashMap<u16, Incoming>,
}

impl Reassembly {
    /// Adds a segment from `src`.
    pub fn add(&mut self, src: u16, s: &Lower) -> Option<Reassembled> {
        let Lower::Segment {
            aid,
            big_mic,
            seq_zero,
            seg_o,
            seg_n,
            data,
        } = s
        else {
            return None;
        };
        let e = self.incoming.entry(src).or_insert_with(|| Incoming {
            seq_zero: *seq_zero,
            aid: *aid,
            big_mic: *big_mic,
            seg_n: *seg_n,
            parts: vec![None; usize::from(*seg_n) + 1],
        });
        if e.seq_zero != *seq_zero || e.seg_n != *seg_n {
            *e = Incoming {
                seq_zero: *seq_zero,
                aid: *aid,
                big_mic: *big_mic,
                seg_n: *seg_n,
                parts: vec![None; usize::from(*seg_n) + 1],
            };
        }
        // Every segment but the last is exactly 12 octets.
        if (*seg_o < *seg_n && data.len() != SEGMENT_SIZE)
            || data.is_empty()
            || data.len() > SEGMENT_SIZE
        {
            return None;
        }
        e.parts[usize::from(*seg_o)] = Some(data.clone());
        let block = e
            .parts
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_some())
            .fold(0u32, |b, (i, _)| b | (1 << i));
        if e.parts.iter().all(Option::is_some) {
            let e = self.incoming.remove(&src)?;
            let upper = e.parts.into_iter().flatten().flatten().collect();
            return Some(Reassembled::Complete {
                aid: e.aid,
                big_mic: e.big_mic,
                upper,
                block,
            });
        }
        Some(Reassembled::Partial { block })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_encryption_round_trips_with_either_key_and_mic() {
        let app = [3u8; 16];
        let dev = [4u8; 16];
        let m = Meta {
            seq: 0x3129ab,
            src: 0x0003,
            dst: 0x1201,
            iv_index: 0x12345678,
            label: None,
        };
        for key in [
            AccessKey::App(&app, crypto::k4(&app)),
            AccessKey::Device(&dev),
        ] {
            for big in [false, true] {
                let c = encrypt_access(key, &m, b"\x82\x02\x01", big);
                assert_eq!(decrypt_access(key, &m, &c, big).unwrap(), b"\x82\x02\x01");
                let other = Meta {
                    seq: m.seq + 1,
                    ..m
                };
                assert!(
                    decrypt_access(key, &other, &c, big).is_none(),
                    "the nonce binds the sequence"
                );
            }
        }
    }

    #[test]
    fn segments_and_reassembles_out_of_order() {
        let upper: Vec<u8> = (0..30u8).collect();
        let segs = segment_access(Some(0x26), false, 0x1234, &upper, false).unwrap();
        assert_eq!(segs.len(), 3);
        let parsed: Vec<Lower> = segs.iter().map(|p| parse(false, p).unwrap()).collect();
        let mut r = Reassembly::default();
        assert_eq!(
            r.add(7, &parsed[2]),
            Some(Reassembled::Partial { block: 0b100 })
        );
        assert_eq!(
            r.add(7, &parsed[0]),
            Some(Reassembled::Partial { block: 0b101 })
        );
        assert_eq!(
            r.add(7, &parsed[1]),
            Some(Reassembled::Complete {
                aid: Some(0x26),
                big_mic: false,
                upper,
                block: 0b111
            })
        );
        // A short PDU fits unsegmented.
        let one = segment_access(None, false, 1, &[1, 2, 3], false).unwrap();
        assert_eq!(
            parse(false, &one[0]),
            Some(Lower::Access {
                aid: None,
                upper: vec![1, 2, 3]
            })
        );
        assert!(segment_access(None, false, 1, &[0; 12 * 33], false).is_none());
    }

    #[test]
    fn acks_round_trip() {
        let p = ack(0x1234, 0b1011);
        assert_eq!(
            parse(true, &p),
            Some(Lower::Ack {
                obo: false,
                seq_zero: 0x1234,
                block: 0b1011
            })
        );
        assert!(parse(true, &p[..4]).is_none());
        assert!(parse(false, &[]).is_none());
    }
}
