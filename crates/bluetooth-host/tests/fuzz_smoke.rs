//! A quick, deterministic pass over the fuzz entry points on stable Rust:
//! random and mutated inputs must never panic. The real fuzzing runs in CI
//! (`fuzz/`, cargo-fuzz); this keeps a regression net on every `cargo test`.
#![cfg(feature = "fuzzing")]

use bluetooth_host::fuzzing;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = (self.next() as usize) % max;
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Seeds shaped like the real thing, so mutations reach deep code.
fn seeds() -> Vec<Vec<u8>> {
    let h = |s: &str| hex::decode(&s[..s.len() / 2 * 2]).unwrap();
    vec![
        h("0201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000010002c5"),
        h("0f16d2fc4000020ca0903bf13015d1a01"),
        h("1416aafe21001b0bb81980ffff0002000301"),
        h("0e3e0d0d01130001665544332211f1010103f8c400000000000000000000000302010"),
        h("043e1a0201000166554433221f1100e0201060703666f6f6f6f6f6fc8"),
        h("0510010400ffff28"),
        h("0b0c0800010000000000ffff"),
        h("0202010000002000"),
    ]
}

#[test]
fn entry_points_never_panic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let seeds = seeds();
    for i in 0..200_000 {
        let mut input = if i % 2 == 0 {
            seeds[i % seeds.len()].clone()
        } else {
            rng.bytes(300)
        };
        for _ in 0..(rng.next() % 4) {
            if input.is_empty() {
                break;
            }
            let at = (rng.next() as usize) % input.len();
            input[at] = rng.next() as u8;
        }
        fuzzing::h4(&input);
        fuzzing::hci_event(&input);
        fuzzing::acl(&input);
        fuzzing::att_server(&input);
        fuzzing::smp_features(&input);
        let adv = bluetooth_adv::Advertisement::parse(&input);
        let mut ctx = bluetooth_adv::beacon::Context::for_address([1, 2, 3, 4, 5, 6]);
        ctx.bthome_keys.insert([1, 2, 3, 4, 5, 6], [7; 16]);
        ctx.kkm_passwords.insert([1, 2, 3, 4, 5, 6], "0000".into());
        for b in bluetooth_adv::beacon::decode(&adv, &ctx) {
            let _ = b.readings();
        }
    }
}
