//! PKCS#1 v1.5 verification footprint on AVR.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use krabi_caliper::avr::FootprintConfig;
use krabi_caliper::report::{Field, UfmtReporter};
use rsa_footprint_avr as _;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../verify_workload.rs"));
define_rsa_verify_workload!(avr);
define_rsa_verify_fixtures!(avr);
define_rsa_verify_operation!();

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let serial = arduino_hal::default_serial!(dp, pins, 57600);
    let fields = [
        Field::token("target", "atmega2560"),
        Field::token("operation", "verify"),
    ];
    let mut reporter = UfmtReporter::new(serial);
    // SAFETY: ATmega2560 SRAM above `_end` is reserved for this single stack.
    unsafe {
        krabi_caliper::avr::run_atmega2560_footprint::<64, _>(
            &dp.TC1,
            &mut reporter,
            FootprintConfig::new("rsa-footprint", &fields).sentinel(0xce),
            verify_fixture,
        )
    }
    .unwrap();
    krabi_caliper::avr::park_simavr()
}
