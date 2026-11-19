//! The Security Manager's cryptographic toolbox (Core Vol 3, Part H, 2.2),
//! on RustCrypto's AES, CMAC and P-256.
//!
//! Values are `u128` (and 32-byte big-endian arrays for P-256 coordinates):
//! the specification writes them as numbers, most significant octet first,
//! and its test vectors read the same way here. SMP PDUs carry them least
//! significant octet first; [`le`] and [`from_le`] convert at that boundary.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use cmac::Mac;
use p256::elliptic_curve::sec1::ToSec1Point;

/// Fills `buf` from the operating system's random number generator.
pub fn random_bytes(buf: &mut [u8]) {
    // A system without a working RNG cannot pair securely at all.
    getrandom::fill(buf).expect("the operating system's random number generator failed");
}

/// A random 128-bit value.
pub fn random_u128() -> u128 {
    let mut b = [0u8; 16];
    random_bytes(&mut b);
    u128::from_le_bytes(b)
}

/// A value's wire form, least significant octet first.
pub fn le(v: u128) -> [u8; 16] {
    v.to_le_bytes()
}

/// A value from its wire form.
pub fn from_le(b: [u8; 16]) -> u128 {
    u128::from_le_bytes(b)
}

/// The security function e: AES-128 of `plaintext` under `key`.
pub fn e(key: u128, plaintext: u128) -> u128 {
    let cipher = Aes128::new(&key.to_be_bytes().into());
    let mut block = aes::Block::from(plaintext.to_be_bytes());
    cipher.encrypt_block(&mut block);
    u128::from_be_bytes(block.into())
}

fn cmac(key: u128, msg: &[u8]) -> u128 {
    let mut m = <cmac::Cmac<Aes128> as KeyInit>::new(&key.to_be_bytes().into());
    m.update(msg);
    u128::from_be_bytes(m.finalize().into_bytes().into())
}

/// The random address hash function ah: `e(k, padding || r) mod 2^24`.
pub fn ah(irk: u128, prand: u32) -> u32 {
    (e(irk, u128::from(prand & 0x00ff_ffff)) & 0x00ff_ffff) as u32
}

/// Whether a resolvable private address (bytes least significant first) was
/// made with `irk`.
pub fn resolves(irk: u128, addr: &[u8; 6]) -> bool {
    let hash = u32::from_le_bytes([addr[0], addr[1], addr[2], 0]);
    let prand = u32::from_le_bytes([addr[3], addr[4], addr[5], 0]);
    prand >> 22 == 0b01 && ah(irk, prand) == hash
}

/// A fresh resolvable private address for `irk` (bytes least significant first).
pub fn new_rpa(irk: u128) -> [u8; 6] {
    let mut p = [0u8; 3];
    random_bytes(&mut p);
    // Two most significant bits 01; the rest of prand must not be all 0s or all 1s.
    p[2] = (p[2] & 0x3f) | 0x40;
    if p[0] == 0 && p[1] == 0 && p[2] == 0x40 {
        p[0] = 1;
    }
    if p[0] == 0xff && p[1] == 0xff && p[2] == 0x7f {
        p[0] = 0xfe;
    }
    let prand = u32::from_le_bytes([p[0], p[1], p[2], 0]);
    let hash = ah(irk, prand).to_le_bytes();
    [hash[0], hash[1], hash[2], p[0], p[1], p[2]]
}

/// LE legacy pairing's confirm value function c1.
///
/// `preq` and `pres` are the Pairing Request and Response PDUs as sent;
/// `iat`/`rat` the initiator's and responder's address types (0 or 1);
/// `ia`/`ra` their addresses, least significant octet first.
#[allow(clippy::too_many_arguments)]
pub fn c1(
    k: u128,
    r: u128,
    preq: &[u8; 7],
    pres: &[u8; 7],
    iat: u8,
    rat: u8,
    ia: &[u8; 6],
    ra: &[u8; 6],
) -> u128 {
    let mut p1 = [0u8; 16];
    p1[0] = iat;
    p1[1] = rat;
    p1[2..9].copy_from_slice(preq);
    p1[9..16].copy_from_slice(pres);
    let mut p2 = [0u8; 16];
    p2[0..6].copy_from_slice(ra);
    p2[6..12].copy_from_slice(ia);
    e(
        k,
        e(k, r ^ u128::from_le_bytes(p1)) ^ u128::from_le_bytes(p2),
    )
}

/// LE legacy pairing's key generation function s1 (the STK).
pub fn s1(k: u128, r1: u128, r2: u128) -> u128 {
    let mask = u128::from(u64::MAX);
    e(k, ((r1 & mask) << 64) | (r2 & mask))
}

/// LE Secure Connections confirm value function f4.
pub fn f4(u: &[u8; 32], v: &[u8; 32], x: u128, z: u8) -> u128 {
    let mut m = [0u8; 65];
    m[..32].copy_from_slice(u);
    m[32..64].copy_from_slice(v);
    m[64] = z;
    cmac(x, &m)
}

/// An address as f5 and f6 take it: 56 bits, the type octet most significant.
pub fn addr56(kind: u8, addr: &[u8; 6]) -> [u8; 7] {
    let mut a = [0u8; 7];
    a[0] = kind & 1;
    for (i, b) in addr.iter().rev().enumerate() {
        a[1 + i] = *b;
    }
    a
}

/// LE Secure Connections key generation function f5: (MacKey, LTK).
pub fn f5(w: &[u8; 32], n1: u128, n2: u128, a1: &[u8; 7], a2: &[u8; 7]) -> (u128, u128) {
    const SALT: u128 = 0x6c88_8391_aaf5_a538_6037_0bdb_5a60_83be;
    let t = cmac(SALT, w);
    let mut m = [0u8; 53];
    m[1..5].copy_from_slice(&0x6274_6c65u32.to_be_bytes());
    m[5..21].copy_from_slice(&n1.to_be_bytes());
    m[21..37].copy_from_slice(&n2.to_be_bytes());
    m[37..44].copy_from_slice(a1);
    m[44..51].copy_from_slice(a2);
    m[51..53].copy_from_slice(&256u16.to_be_bytes());
    let mac_key = cmac(t, &m);
    m[0] = 1;
    let ltk = cmac(t, &m);
    (mac_key, ltk)
}

/// LE Secure Connections check value function f6.
pub fn f6(
    w: u128,
    n1: u128,
    n2: u128,
    r: u128,
    io_cap: &[u8; 3],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> u128 {
    let mut m = [0u8; 65];
    m[..16].copy_from_slice(&n1.to_be_bytes());
    m[16..32].copy_from_slice(&n2.to_be_bytes());
    m[32..48].copy_from_slice(&r.to_be_bytes());
    m[48..51].copy_from_slice(io_cap);
    m[51..58].copy_from_slice(a1);
    m[58..65].copy_from_slice(a2);
    cmac(w, &m)
}

/// LE Secure Connections numeric comparison value function g2 (the six
/// digits shown are this mod 1 000 000).
pub fn g2(u: &[u8; 32], v: &[u8; 32], x: u128, y: u128) -> u32 {
    let mut m = [0u8; 80];
    m[..32].copy_from_slice(u);
    m[32..64].copy_from_slice(v);
    m[64..80].copy_from_slice(&y.to_be_bytes());
    cmac(x, &m) as u32
}

/// Link key conversion function h6.
pub fn h6(w: u128, key_id: u32) -> u128 {
    cmac(w, &key_id.to_be_bytes())
}

/// Link key conversion function h7.
pub fn h7(salt: u128, w: u128) -> u128 {
    cmac(salt, &w.to_be_bytes())
}

/// The private key the specification publishes for debugging. A peer that
/// sends its public key is not secure, and pairing refuses it.
pub const DEBUG_PUBLIC_X: [u8; 32] = [
    0x20, 0xb0, 0x03, 0xd2, 0xf2, 0x97, 0xbe, 0x2c, 0x5e, 0x2c, 0x83, 0xa7, 0xe9, 0xf9, 0xa5, 0xb9,
    0xef, 0xf4, 0x91, 0x11, 0xac, 0xf4, 0xfd, 0xdb, 0xcc, 0x03, 0x01, 0x48, 0x0e, 0x35, 0x9d, 0xe6,
];

/// An ephemeral P-256 key pair for one pairing.
pub struct EcdhKey {
    secret: p256::SecretKey,
    /// The public key's x coordinate, big-endian.
    pub x: [u8; 32],
    /// The public key's y coordinate, big-endian.
    pub y: [u8; 32],
}

impl EcdhKey {
    /// A fresh key pair.
    pub fn generate() -> Self {
        loop {
            let mut b = [0u8; 32];
            random_bytes(&mut b);
            if let Ok(secret) = p256::SecretKey::from_slice(&b) {
                return Self::from_secret(secret);
            }
        }
    }

    fn from_secret(secret: p256::SecretKey) -> Self {
        let point = secret.public_key().to_sec1_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().map(|v| v.as_slice()).unwrap_or(&[0; 32]));
        y.copy_from_slice(point.y().map(|v| v.as_slice()).unwrap_or(&[0; 32]));
        EcdhKey { secret, x, y }
    }

    /// From a known private key (tests, and the debug key).
    pub fn from_private(d: &[u8; 32]) -> Option<Self> {
        p256::SecretKey::from_slice(d).ok().map(Self::from_secret)
    }

    /// The DHKey with a peer's public key, big-endian; `None` when the
    /// peer's point is not on the curve (an invalid-curve attack, or garbage).
    pub fn dh_key(&self, peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Option<[u8; 32]> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(peer_x);
        sec1[33..].copy_from_slice(peer_y);
        let peer = p256::PublicKey::from_sec1_bytes(&sec1).ok()?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }
    fn n(s: &str) -> u128 {
        u128::from_str_radix(&s.replace(' ', ""), 16).unwrap()
    }
    fn a32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    const U: &str = "20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6";
    const V: &str = "55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd";
    const X: &str = "d5cb8454 d177733e ffffb2ec 712baeab";
    const N2: &str = "a6e8e7cc 25a75f6e 216583f7 ff3dc4cf";
    const W: &str = "ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698";

    // Core Vol 3, Part H, Appendix D.
    #[test]
    fn f4_vector() {
        assert_eq!(
            f4(&a32(U), &a32(V), n(X), 0),
            n("f2c916f1 07a9bd1c f1eda1be a974872d")
        );
    }

    #[test]
    fn f5_vector() {
        let a1: [u8; 7] = h("00561237 37bfce").try_into().unwrap();
        let a2: [u8; 7] = h("00a71370 2dcfc1").try_into().unwrap();
        let (mac, ltk) = f5(&a32(W), n(X), n(N2), &a1, &a2);
        assert_eq!(mac, n("2965f176 a1084a02 fd3f6a20 ce636e20"));
        assert_eq!(ltk, n("69867911 69d7cd23 980522b5 94750a38"));
    }

    #[test]
    fn f6_vector() {
        let a1: [u8; 7] = h("00561237 37bfce").try_into().unwrap();
        let a2: [u8; 7] = h("00a71370 2dcfc1").try_into().unwrap();
        let v = f6(
            n("2965f176 a1084a02 fd3f6a20 ce636e20"),
            n(X),
            n(N2),
            n("12a3343b b453bb54 08da42d2 0c2d0fc8"),
            &[0x01, 0x01, 0x02],
            &a1,
            &a2,
        );
        assert_eq!(v, n("e3c47398 9cd0e8c5 d26c0b09 da958f61"));
    }

    #[test]
    fn g2_vector() {
        assert_eq!(g2(&a32(U), &a32(V), n(X), n(N2)), 0x2f9e_d5ba);
    }

    #[test]
    fn h6_h7_vectors() {
        let w = n("ec0234a3 57c8ad05 341010a6 0a397d9b");
        assert_eq!(h6(w, 0x6c65_6272), n("2d9ae102 e76dc91c e8d3a9e2 80b16399"));
        assert_eq!(h7(0x746d_7031, w), n("fb173597 c6a3c0ec d2998c2a 75a57011"));
    }

    #[test]
    fn ah_vector_and_rpa() {
        let irk = n("ec0234a3 57c8ad05 341010a6 0a397d9b");
        assert_eq!(ah(irk, 0x70_8194), 0x0d_fbaa);
        let rpa = new_rpa(irk);
        assert!(resolves(irk, &rpa));
        assert!(!resolves(irk ^ 1, &rpa));
    }

    // Core Vol 3, Part H, 2.2.3 and 2.2.4.
    #[test]
    fn c1_s1_vectors() {
        let preq: [u8; 7] = [0x01, 0x01, 0x00, 0x00, 0x10, 0x07, 0x07];
        let pres: [u8; 7] = [0x02, 0x03, 0x00, 0x00, 0x08, 0x00, 0x05];
        let ia = [0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1];
        let ra = [0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1];
        let c = c1(
            0,
            n("5783D52156AD6F0E6388274EC6702EE0"),
            &preq,
            &pres,
            1,
            0,
            &ia,
            &ra,
        );
        assert_eq!(c, n("1e1e3fef878988ead2a74dc5bef13b86"));
        let s = s1(
            0,
            n("000F0E0D0C0B0A091122334455667788"),
            n("010203040506070899AABBCCDDEEFF00"),
        );
        assert_eq!(s, n("9a1fe1f0e8b0f49b5b4216ae796da062"));
    }

    #[test]
    fn ecdh_with_the_debug_key() {
        let d = a32("3f49f6d4 a3c55f38 74c9b3e3 d2103f50 4aff607b eb40b799 5899b8a6 cd3c1abd");
        let debug = EcdhKey::from_private(&d).unwrap();
        assert_eq!(debug.x, DEBUG_PUBLIC_X);
        let a = EcdhKey::generate();
        let b = EcdhKey::generate();
        assert_eq!(a.dh_key(&b.x, &b.y), b.dh_key(&a.x, &a.y));
        assert!(a.dh_key(&[1; 32], &[2; 32]).is_none());
    }
}
