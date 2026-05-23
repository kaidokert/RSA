#![no_main]
#![no_std]

use cortex_m_rt::entry;
use rsa_footprint_cortex_m::{fake_verify, test_fixture, MESSAGE, MODULUS, SIGNATURE};

#[entry]
fn main() -> ! {
    test_fixture(|| fake_verify(MODULUS, MESSAGE, SIGNATURE), "baseline");
    loop {}
}
