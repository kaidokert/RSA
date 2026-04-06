#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
use rsa::signature::DigestVerifier;
use rsa_footprint_avr as _;
use rsa_footprint_avr::stack_measurement::*;
use rsa_footprint_avr::{MESSAGE, MODULUS, SIGNATURE};
use sha1::Sha1;

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    // Use TC1 (16-bit) in normal mode, prescaler 1024 → 15625 Hz at 16MHz
    // Max measurable: 65536/15625 = 4.19 seconds. 1 tick = 64µs.
    let tc1 = &dp.TC1;
    tc1.tccr1b.write(|w| w.cs1().prescale_1024());

    unsafe { fill_stack_with_watermark() };

    let start: u16 = tc1.tcnt1.read().bits();
    let result = {
        type U512 = FixedUInt<u8, 64>;
        let key = public_key_from_be_bytes::<U512>(&MODULUS, 3).unwrap();
        let verifying_key = GenericVerifyingKey::<Sha1, _, _>::new(key);
        let signature = GenericSignature::from(U512::from_be_bytes(&SIGNATURE));
        verifying_key
            .verify_digest(
                |digest: &mut Sha1| {
                    use sha1::Digest;
                    digest.update(MESSAGE);
                    Ok(())
                },
                &signature,
            )
            .is_ok()
    };
    let end: u16 = tc1.tcnt1.read().bits();

    let stack_used = unsafe { measure_stack_usage() };

    // ticks * 1000 / 15625 = ms, but use integer math: ticks * 8 / 125
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
