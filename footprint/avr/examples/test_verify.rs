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

    unsafe { fill_stack_with_watermark() };
    let counter = rsa_footprint_avr::cyclecount::CycleCounter::start(&dp.TC1);
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
