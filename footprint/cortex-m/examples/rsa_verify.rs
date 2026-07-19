//! PKCS#1 v1.5 verification footprint on Cortex-M.

#![no_main]
#![no_std]

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../verify_workload.rs"));
define_rsa_verify_workload!(full);
define_rsa_verify_fixtures!(full);
define_rsa_verify_operation!();

#[cortex_m_rt::entry]
fn main() -> ! {
    rsa_footprint_cortex_m::test_fixture_arg::<2048>(verify_fixture, BACKEND);
    loop {
        cortex_m::asm::nop();
    }
}
