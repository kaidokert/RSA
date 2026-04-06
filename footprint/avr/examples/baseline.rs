#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use rsa_footprint_avr as _;
use rsa_footprint_avr::stack_measurement::*;
use rsa_footprint_avr::{fake_verify, MESSAGE, MODULUS, SIGNATURE};

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    let tc1 = &dp.TC1;
    tc1.tccr1b.write(|w| w.cs1().prescale_1024());

    unsafe { fill_stack_with_watermark() };

    let start: u16 = tc1.tcnt1.read().bits();
    let result = fake_verify(MODULUS, MESSAGE, SIGNATURE);
    let end: u16 = tc1.tcnt1.read().bits();

    let stack_used = unsafe { measure_stack_usage() };
    let ticks = end.wrapping_sub(start);
    let ms = (ticks as u32) * 8 / 125;

    if result {
        ufmt::uwriteln!(&mut serial, "rsa ACCEPT").ok();
    } else {
        ufmt::uwriteln!(&mut serial, "rsa REJECT").ok();
    }
    ufmt::uwriteln!(&mut serial, "Time: {} ms ({} ticks)", ms, ticks).ok();
    ufmt::uwriteln!(&mut serial, "Max stack usage: {} bytes", stack_used).ok();

    loop {
        unsafe { core::arch::asm!("sleep") }
    }
}
