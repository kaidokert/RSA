#![no_main]
#![no_std]

use rsa_footprint_riscv::{fake_verify, test_fixture, MESSAGE, MODULUS, SIGNATURE};

#[riscv_rt::entry]
fn main() -> ! {
    test_fixture(|| fake_verify(MODULUS, MESSAGE, SIGNATURE), "baseline");
}
