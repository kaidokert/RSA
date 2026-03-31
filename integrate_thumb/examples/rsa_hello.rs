#![no_std]
#![no_main]

use core::convert::Infallible;

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::rand_core::{TryCryptoRng, TryRng};
use rsa::{
    pkcs1v15_encrypt_pad_noalloc, pkcs1v15_encrypt_unpad_noalloc,
    pkcs1v15_generate_prefix_noalloc, pkcs1v15_sign_pad_noalloc, rsa_encrypt, ModMathFixedUint,
    uint_to_be_pad_noalloc, uint_to_zeroizing_be_pad_noalloc,
};
use sha1::Sha1;

struct DummyRng;

impl TryRng for DummyRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(1)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(1)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest {
            *byte = 1;
        }
        Ok(())
    }
}

impl TryCryptoRng for DummyRng {}

#[cortex_m_rt::entry]
fn main() -> ! {
    run().unwrap();
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

fn run() -> rsa::Result<()> {
    let mut buf = [0u8; 4];
    let mut em = [0u8; 16];
    let mut unpadded = [0u8; 16];
    let mut sig = [0u8; 64];
    let mut prefix_storage = [0u8; 32];
    let mut rng = DummyRng;

    let out = uint_to_be_pad_noalloc::<ModMathFixedUint<1>>(1u8.into(), 4, &mut buf)?;
    assert_eq!(out, &[0, 0, 0, 1]);

    let out = uint_to_zeroizing_be_pad_noalloc::<ModMathFixedUint<1>>(1u8.into(), 4, &mut buf)?;
    assert_eq!(out, &[0, 0, 0, 1]);

    let padded = pkcs1v15_encrypt_pad_noalloc(&mut rng, &[0xAA], 16, &mut em)?;
    let msg = pkcs1v15_encrypt_unpad_noalloc(padded, 16, &mut unpadded)?;
    assert_eq!(msg, &[0xAA]);

    let prefix = pkcs1v15_generate_prefix_noalloc::<Sha1>(&mut prefix_storage)?;
    let em = pkcs1v15_sign_pad_noalloc(prefix, &[1u8; 20], 64, &mut sig)?;
    assert_eq!(em[0], 0x00);
    assert_eq!(em[1], 0x01);

    let key = public_key_from_be_bytes(&[0x0c, 0xa1], 17)?;
    let msg = ModMathFixedUint::<2>::from_be_slice(&[0x00, 0x2a]);
    let out = rsa_encrypt(&key, &msg)?;
    assert_eq!(out, ModMathFixedUint::<2>::from_be_slice(&[0x09, 0xfd]));

    hprintln!("rsa_hello ok");
    Ok(())
}
