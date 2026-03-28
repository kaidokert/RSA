#![no_std]
#![no_main]

use core::convert::Infallible;

use panic_semihosting as _;
use rsa::rand_core::{TryCryptoRng, TryRng};
use sha1::Sha1;
use rsa::{
    pkcs1v15_encrypt_pad_noalloc, pkcs1v15_encrypt_unpad_noalloc,
    pkcs1v15_generate_prefix_noalloc, pkcs1v15_sign_pad_noalloc, uint_to_be_pad_noalloc,
    uint_to_zeroizing_be_pad_noalloc,
};

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
    let mut buf = [0u8; 4];
    let mut em = [0u8; 16];
    let mut sig = [0u8; 32];
    let mut prefix = [0u8; 32];
    let mut rng = DummyRng;
    loop {
        let _ = uint_to_be_pad_noalloc::<u8>(1u8.into(), 4, &mut buf);
        let _ = uint_to_zeroizing_be_pad_noalloc::<u8>(1u8.into(), 4, &mut buf);
        let _ = pkcs1v15_encrypt_pad_noalloc(&mut rng, &[1u8], 16, &mut em);
        let _ = pkcs1v15_encrypt_unpad_noalloc(&em, 16, &mut sig);
        let prefix = pkcs1v15_generate_prefix_noalloc::<Sha1>(&mut prefix).unwrap();
        let _ = pkcs1v15_sign_pad_noalloc(prefix, &[1u8; 20], 32, &mut sig);
    }
}
