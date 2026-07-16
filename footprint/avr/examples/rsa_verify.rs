//! Unified PKCS#1 v1.5 verify example for all measured key sizes on AVR.
//! Picks the fixture and `FixedUInt` type from cfg features so the same source
//! file builds for every entry in the suite. AVR uses u8 limbs throughout.
//!
//! Exactly one `key_*` feature must be enabled.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Compile-time invariants for feature selectors — fail with a clear message
// instead of a downstream missing-type / duplicate-item error.
const _: () = {
    const N: usize = cfg!(feature = "key_512") as usize
        + cfg!(feature = "key_768") as usize
        + cfg!(feature = "key_1024") as usize
        + cfg!(feature = "key_1536") as usize;
    assert!(N == 1, "exactly one `key_*` feature must be enabled");
};
const _: () = {
    const N: usize = cfg!(feature = "hash_sha1") as usize + cfg!(feature = "hash_sha256") as usize;
    assert!(N == 1, "exactly one `hash_*` feature must be enabled");
};
#[cfg(all(feature = "hash_sha1", not(feature = "key_512")))]
compile_error!("hash_sha1 only paired with key_512 (no fixture exists for other key sizes)");

use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
use rsa::signature::Verifier;
use rsa_footprint_avr as _;
use rsa_footprint_avr::stack_measurement::*;

#[cfg(feature = "hash_sha1")]
type Hash = sha1::Sha1;
#[cfg(feature = "hash_sha256")]
type Hash = sha2::Sha256;

mod fixture {
    #[cfg(all(feature = "key_512", feature = "hash_sha1"))]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa512_sha1.rs"
    ));
    #[cfg(all(feature = "key_512", feature = "hash_sha256"))]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa512_sha256.rs"
    ));
    #[cfg(feature = "key_768")]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa768_sha256.rs"
    ));
    #[cfg(feature = "key_1024")]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa1024_sha256.rs"
    ));
    #[cfg(feature = "key_1536")]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa1536_sha256.rs"
    ));
}

#[cfg(feature = "key_512")]
type Key = FixedUInt<u8, 64>;
#[cfg(feature = "key_768")]
type Key = FixedUInt<u8, 96>;
#[cfg(feature = "key_1024")]
type Key = FixedUInt<u8, 128>;
#[cfg(feature = "key_1536")]
type Key = FixedUInt<u8, 192>;

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    let stack_probe = fill_stack_with_watermark();
    let counter = rsa_footprint_avr::cyclecount::CycleCounter::start(&dp.TC1);
    let result = {
        let key =
            public_key_from_be_bytes::<Key>(&fixture::MODULUS, fixture::PUBLIC_EXPONENT).unwrap();
        let verifying_key = GenericVerifyingKey::<Hash, _, _>::new(key);
        let signature = GenericSignature::from(Key::from_be_bytes(&fixture::SIGNATURE));
        verifying_key.verify(fixture::MESSAGE, &signature).is_ok()
    };
    let ticks = counter.elapsed_ticks(&dp.TC1);
    let ms = counter.elapsed_ms(&dp.TC1);
    let stack_used = measure_stack_usage(&stack_probe);

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
