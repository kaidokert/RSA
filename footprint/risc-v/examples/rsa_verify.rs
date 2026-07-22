//! PKCS#1 v1.5 verification footprint on RISC-V.

#![no_main]
#![no_std]

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../verify_workload.rs"
));
define_rsa_verify_workload!(full);
define_rsa_verify_fixtures!(full);
define_rsa_verify_operation!();

#[riscv_rt::entry]
fn main() -> ! {
    rsa_footprint_riscv::test_fixture(verify_fixture, BACKEND)
}
