#![no_std]
#![no_main]

use core::convert::Infallible;

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use rsa::rand_core::{TryCryptoRng, TryRng};
use rsa::{
    pkcs1v15_encrypt_pad_noalloc, pkcs1v15_encrypt_unpad_noalloc, pkcs1v15_generate_prefix_noalloc,
    pkcs1v15_sign_pad_noalloc,
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
    let mut rng = DummyRng;

    let mut em = [0u8; 12];
    let padded = pkcs1v15_encrypt_pad_noalloc(&mut rng, &[0xAA], 12, &mut em).unwrap();
    assert_eq!(padded, &[0x00, 0x02, 1, 1, 1, 1, 1, 1, 1, 1, 0x00, 0xAA]);

    let mut unpadded = [0u8; 12];
    let msg = pkcs1v15_encrypt_unpad_noalloc(padded, 12, &mut unpadded).unwrap();
    assert_eq!(msg, &[0xAA]);

    let mut prefix_storage = [0u8; 32];
    let prefix = pkcs1v15_generate_prefix_noalloc::<Sha1>(&mut prefix_storage).unwrap();
    assert_eq!(
        prefix,
        &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14]
    );

    let mut sig_storage = [0u8; 64];
    let hashed = [0xAA; 20];
    let em = pkcs1v15_sign_pad_noalloc(prefix, &hashed, 64, &mut sig_storage).unwrap();
    assert_eq!(em[0], 0x00);
    assert_eq!(em[1], 0x01);
    assert!(em[2..28].iter().all(|&b| b == 0xFF));
    assert_eq!(em[28], 0x00);
    assert_eq!(&em[29..44], prefix);
    assert_eq!(&em[44..64], &hashed);

    hprintln!("pkcs1v15_primitives ok");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
