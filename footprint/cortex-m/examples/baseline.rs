#![no_main]
#![no_std]

use cortex_m_rt::entry;
use rsa_footprint_cortex_m::{fake_verify, test_fixture};

mod fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa512_sha1.rs"
    ));
}

#[entry]
fn main() -> ! {
    test_fixture(
        || fake_verify(fixture::MODULUS, fixture::MESSAGE, fixture::SIGNATURE),
        "baseline",
    );
    loop {
        cortex_m::asm::nop();
    }
}
