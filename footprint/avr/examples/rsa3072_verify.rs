#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
use rsa::signature::Verifier;
use rsa_footprint_avr as _;
use rsa_footprint_avr::stack_measurement::*;
use sha2::Sha256;

mod fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa3072_sha256.rs"
    ));
}

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    let tc1 = &dp.TC1;
    tc1.tccr1b.write(|w| w.cs1().prescale_1024());

    unsafe { fill_stack_with_watermark() };

    let start: u16 = tc1.tcnt1.read().bits();
    let result = {
        type U3072 = FixedUInt<u8, 384>;
        let key = public_key_from_be_bytes::<U3072>(
            &fixture::RSA3072_MODULUS,
            fixture::RSA3072_PUBLIC_EXPONENT,
        )
        .unwrap();
        let verifying_key = GenericVerifyingKey::<Sha256, _, _>::new(key);
        let signature = GenericSignature::from(U3072::from_be_bytes(&fixture::RSA3072_SIGNATURE));
        verifying_key
            .verify(fixture::RSA3072_MESSAGE, &signature)
            .is_ok()
    };
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
