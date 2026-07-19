#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use krabi_caliper::avr::timer_measurement;
use krabi_caliper::report::{Field, UfmtReporter};
use rsa_footprint_avr as _;
use rsa_footprint_avr::fake_verify;

mod fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa512_sha1.rs"
    ));
}

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let serial = arduino_hal::default_serial!(dp, pins, 57600);

    // SAFETY: ATmega2560 SRAM above `_end` is reserved for this single stack.
    let stack_probe =
        unsafe { krabi_caliper::stack::paint_avr_runtime::<64>(0x2200, 0xce) }.unwrap();
    let counter = krabi_caliper::avr::Atmega2560Timer1Counter::start(&dp.TC1);
    let result = fake_verify(fixture::MODULUS, fixture::MESSAGE, fixture::SIGNATURE);
    let ticks = counter.elapsed_ticks();
    let ms = counter.elapsed_ms();
    let stack = stack_probe.measure();
    let fields = [
        Field::token("target", "atmega2560"),
        Field::token("operation", "baseline"),
    ];
    let mut reporter = UfmtReporter::new(serial);
    krabi_caliper::report_completed!(
        &mut reporter,
        benchmark: "rsa-footprint",
        passed: result,
        fields: &fields,
        stack: stack,
        measurements: [("timer1", timer_measurement(ticks as u64, 15_625, false))]
    )
    .unwrap();
    let mut serial = reporter.into_inner();

    if result {
        ufmt::uwriteln!(&mut serial, "rsa ACCEPT").ok();
    } else {
        ufmt::uwriteln!(&mut serial, "rsa REJECT").ok();
    }
    ufmt::uwriteln!(&mut serial, "Time: {} ms ({} ticks)", ms, ticks).ok();
    ufmt::uwriteln!(
        &mut serial,
        "Max stack usage: {} bytes",
        stack.high_water_bytes
    )
    .ok();

    loop {
        unsafe { core::arch::asm!("sleep") }
    }
}
