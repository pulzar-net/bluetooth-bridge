#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let adv = bluetooth_adv::Advertisement::parse(data);
    let mut ctx = bluetooth_adv::beacon::Context::for_address([1, 2, 3, 4, 5, 6]);
    ctx.bthome_keys.insert([1, 2, 3, 4, 5, 6], [7; 16]);
    ctx.kkm_passwords.insert([1, 2, 3, 4, 5, 6], "0000".into());
    for b in bluetooth_adv::beacon::decode(&adv, &ctx) {
        let _ = b.readings();
    }
});
