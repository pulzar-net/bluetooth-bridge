//! The Mesh security toolbox (Mesh Protocol 3.9.2): the salt generation
//! function s1, the key derivation functions k1 to k4, and AES-CCM with
//! the 32 and 64-bit MICs Mesh uses. Keys and values are byte arrays most
//! significant octet first, as the specification and its sample data write
//! them (Mesh, unlike SMP, sends them in that order too).

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use ccm::aead::{Aead, Payload};
use ccm::consts::{U13, U4, U8};
use cmac::Mac;

/// A 128-bit key or value.
pub type Key = [u8; 16];

/// e: AES-128 of one block.
pub fn e(key: &Key, block: &[u8; 16]) -> [u8; 16] {
    let mut b = aes::Block::from(*block);
    Aes128::new(&(*key).into()).encrypt_block(&mut b);
    b.into()
}

/// AES-CMAC.
pub fn cmac(key: &Key, msg: &[u8]) -> Key {
    let mut m = <cmac::Cmac<Aes128> as KeyInit>::new(&(*key).into());
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// s1: the salt generation function.
pub fn s1(m: &[u8]) -> Key {
    cmac(&[0; 16], m)
}

/// k1: derives a key from `n` with `salt` and `p`.
pub fn k1(n: &[u8], salt: &Key, p: &[u8]) -> Key {
    let t = cmac(salt, n);
    cmac(&t, p)
}

/// What k2 derives from a network key: NID, EncryptionKey and PrivacyKey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkMaterial {
    /// The 7-bit network identifier in each Network PDU.
    pub nid: u8,
    /// The network encryption key.
    pub encryption_key: Key,
    /// The network privacy key (obfuscation).
    pub privacy_key: Key,
}

/// k2: the network key material; `p` is 0x00 for the master credentials,
/// or 0x01 followed by the LPN and friend addresses and counters for
/// friendship credentials.
pub fn k2(n: &Key, p: &[u8]) -> NetworkMaterial {
    let salt = s1(b"smk2");
    let t = cmac(&salt, n);
    let mut m = Vec::with_capacity(p.len() + 17);
    m.extend_from_slice(p);
    m.push(1);
    let t1 = cmac(&t, &m);
    m.clear();
    m.extend_from_slice(&t1);
    m.extend_from_slice(p);
    m.push(2);
    let t2 = cmac(&t, &m);
    m.clear();
    m.extend_from_slice(&t2);
    m.extend_from_slice(p);
    m.push(3);
    let t3 = cmac(&t, &m);
    NetworkMaterial {
        nid: t1[15] & 0x7f,
        encryption_key: t2,
        privacy_key: t3,
    }
}

/// k3: the 64-bit Network ID of a network key.
pub fn k3(n: &Key) -> [u8; 8] {
    let t = cmac(&s1(b"smk3"), n);
    let r = cmac(&t, b"id64\x01");
    let mut out = [0u8; 8];
    out.copy_from_slice(&r[8..]);
    out
}

/// k4: the 6-bit AID of an application key.
pub fn k4(n: &Key) -> u8 {
    let t = cmac(&s1(b"smk4"), n);
    cmac(&t, b"id6\x01")[15] & 0x3f
}

/// The identity key (node identity) and beacon key (secure network beacons).
pub fn identity_key(net_key: &Key) -> Key {
    k1(net_key, &s1(b"nkik"), b"id128\x01")
}

/// The beacon key.
pub fn beacon_key(net_key: &Key) -> Key {
    k1(net_key, &s1(b"nkbk"), b"id128\x01")
}

/// The device key a provisioner and device share after provisioning.
pub fn device_key(ecdh_secret: &[u8; 32], provisioning_salt: &Key) -> Key {
    k1(ecdh_secret, provisioning_salt, b"prdk")
}

/// AES-CCM with a 13-octet nonce and a 4 or 8-octet MIC: ciphertext then MIC.
pub fn ccm_encrypt(
    key: &Key,
    nonce: &[u8; 13],
    aad: &[u8],
    plain: &[u8],
    mic_len: usize,
) -> Vec<u8> {
    let p = Payload { msg: plain, aad };
    let r = if mic_len == 8 {
        ccm::Ccm::<Aes128, U8, U13>::new(&(*key).into()).encrypt(nonce.into(), p)
    } else {
        ccm::Ccm::<Aes128, U4, U13>::new(&(*key).into()).encrypt(nonce.into(), p)
    };
    // Lengths in Mesh are far below CCM's limit.
    r.unwrap_or_default()
}

/// AES-CCM decryption of ciphertext then MIC; `None` when it does not authenticate.
pub fn ccm_decrypt(
    key: &Key,
    nonce: &[u8; 13],
    aad: &[u8],
    sealed: &[u8],
    mic_len: usize,
) -> Option<Vec<u8>> {
    if sealed.len() < mic_len {
        return None;
    }
    let p = Payload { msg: sealed, aad };
    if mic_len == 8 {
        ccm::Ccm::<Aes128, U8, U13>::new(&(*key).into())
            .decrypt(nonce.into(), p)
            .ok()
    } else {
        ccm::Ccm::<Aes128, U4, U13>::new(&(*key).into())
            .decrypt(nonce.into(), p)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s.replace(' ', "")).unwrap().try_into().unwrap()
    }

    // Mesh Protocol, 8.1 (sample data for the security toolbox).
    #[test]
    fn s1_sample() {
        assert_eq!(s1(b"test"), h::<16>("b73cefbd641ef2ea598c2b6efb62f79c"));
    }

    #[test]
    fn k1_sample() {
        let n: [u8; 16] = h("3216d1509884b533248541792b877f98");
        let salt: [u8; 16] = h("2ba14ffa0df84a2831938d57d276cab4");
        let p: [u8; 16] = h("5a09d60797eeb4478aada59db3352a0d");
        assert_eq!(
            k1(&n, &salt, &p),
            h::<16>("f6ed15a8934afbe7d83e8dcb57fcf5d7")
        );
    }

    #[test]
    fn k2_master_sample() {
        let m = k2(&h("f7a2a44f8e8a8029064f173ddc1e2b00"), &[0]);
        assert_eq!(m.nid, 0x7f);
        assert_eq!(
            m.encryption_key,
            h::<16>("9f589181a0f50de73c8070c7a6d27f46")
        );
        assert_eq!(m.privacy_key, h::<16>("4c715bd4a64b938f99b453351653124f"));
    }

    #[test]
    fn k3_k4_samples() {
        assert_eq!(
            k3(&h("f7a2a44f8e8a8029064f173ddc1e2b00")),
            h::<8>("ff046958233db014")
        );
        assert_eq!(k4(&h("3216d1509884b533248541792b877f98")), 0x38);
    }

    #[test]
    fn ccm_round_trip_and_tamper() {
        let k = [7u8; 16];
        let n = [1u8; 13];
        for mic in [4, 8] {
            let c = ccm_encrypt(&k, &n, b"", b"hello mesh", mic);
            assert_eq!(c.len(), 10 + mic);
            assert_eq!(ccm_decrypt(&k, &n, b"", &c, mic).unwrap(), b"hello mesh");
            let mut bad = c.clone();
            bad[0] ^= 1;
            assert!(ccm_decrypt(&k, &n, b"", &bad, mic).is_none());
        }
        assert!(ccm_decrypt(&k, &n, b"", &[1, 2], 4).is_none());
    }
}
