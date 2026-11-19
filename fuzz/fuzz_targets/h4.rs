#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    bluetooth_host::fuzzing::h4(data);
});
