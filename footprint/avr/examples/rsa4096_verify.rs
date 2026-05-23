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
        "/../fixtures/rsa4096_sha256.rs"
    ));
}

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    unsafe { fill_stack_with_watermark() };
    let counter = rsa_footprint_avr::cyclecount::CycleCounter::start(&dp.TC1);
    let result = {
        type U4096 = FixedUInt<u8, 512>;
        let key = public_key_from_be_bytes::<U4096>(
            &fixture::RSA4096_MODULUS,
            fixture::RSA4096_PUBLIC_EXPONENT,
        )
        .unwrap();
        let verifying_key = GenericVerifyingKey::<Sha256, _, _>::new(key);
        let signature = GenericSignature::from(U4096::from_be_bytes(&fixture::RSA4096_SIGNATURE));
        verifying_key
            .verify(fixture::RSA4096_MESSAGE, &signature)
            .is_ok()
    };
    let ticks = counter.elapsed_ticks(&dp.TC1);
    let ms = counter.elapsed_ms(&dp.TC1);
    let stack_used = unsafe { measure_stack_usage() };

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
