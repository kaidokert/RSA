#![no_std]
#![no_main]

//! End-to-end no_alloc OAEP smoke test on cortex-m — exercises the full
//! scheme layer (`rsa::oaep::GenericEncryptingKey`), not just the padding
//! helper. RSA-512 + SHA-1 + e=3 with a deterministic counter RNG so the
//! ciphertext is reproducible; expected vector captured from the same
//! GenericEncryptingKey running on host.

use core::convert::Infallible;

use cortex_m_semihosting::{debug, hprintln};
use fixed_bigint::FixedUInt;
use panic_semihosting as _;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::oaep::GenericEncryptingKey;
use rsa::rand_core::{TryCryptoRng, TryRng};
use rsa::traits::RandomizedEncryptor;
use sha1::Sha1;

const MODULUS: [u8; 64] = [
    0x96, 0x9d, 0x03, 0xff, 0xa9, 0x8d, 0x88, 0x8f, 0x3a, 0xa4, 0xf2, 0xfe, 0xd2, 0x32, 0xe6, 0x1c,
    0x4a, 0xcf, 0x06, 0x63, 0xa9, 0x2f, 0x99, 0x03, 0x4c, 0xf7, 0xb7, 0x24, 0x5a, 0x1a, 0x1e, 0x5e,
    0xaf, 0xa5, 0x65, 0xaf, 0xb9, 0x0b, 0xab, 0x22, 0x85, 0x71, 0x2f, 0xaa, 0x50, 0x39, 0x39, 0xa0,
    0x65, 0xfb, 0x60, 0xdd, 0x08, 0x28, 0xa3, 0x84, 0xf2, 0x6d, 0x8a, 0xfc, 0x28, 0x6d, 0xf6, 0xcf,
];

const EXPECTED_CIPHERTEXT: [u8; 64] = [
    0x3e, 0x0d, 0xc0, 0xab, 0xae, 0x02, 0xbf, 0x30, 0x4c, 0xc0, 0xa7, 0x66, 0x37, 0x3f, 0x97, 0x61,
    0x6c, 0x2a, 0xe0, 0xd3, 0xf0, 0x80, 0xee, 0x32, 0x65, 0xc3, 0xc9, 0x22, 0xa8, 0x21, 0x03, 0x1f,
    0x1e, 0x6e, 0x20, 0x1a, 0xe9, 0xaa, 0xf3, 0x40, 0xb8, 0x63, 0x63, 0x26, 0xff, 0x78, 0x64, 0x97,
    0x8e, 0xaa, 0x53, 0x3a, 0x5b, 0x6b, 0x41, 0x20, 0x2e, 0x37, 0xc0, 0x9f, 0xa3, 0x9e, 0xec, 0xdb,
];

struct CounterRng(u8);

impl TryRng for CounterRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        for b in dest {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
            if self.0 == 0 {
                self.0 = 1;
            }
        }
        Ok(())
    }
}
impl TryCryptoRng for CounterRng {}

#[cortex_m_rt::entry]
fn main() -> ! {
    type U512 = FixedUInt<u8, 64>;

    let key = match public_key_from_be_bytes::<U512>(&MODULUS, 3) {
        Ok(k) => GenericEncryptingKey::<Sha1, Sha1, _, _>::new(k),
        Err(e) => {
            hprintln!("oaep_encrypt_smoke: key build failed: {:?}", e);
            debug::exit(debug::EXIT_FAILURE);
            loop {}
        }
    };
    let mut rng = CounterRng(1);
    let mut storage = [0u8; 64];

    match key.encrypt_with_rng_into(&mut rng, b"hello world!", &mut storage) {
        Ok(ct) if ct == EXPECTED_CIPHERTEXT => {
            hprintln!("oaep_encrypt_smoke: ok");
            debug::exit(debug::EXIT_SUCCESS);
        }
        Ok(_) => {
            hprintln!("oaep_encrypt_smoke: mismatch");
            hprintln!("  got: {:02x?}", &storage[..]);
            debug::exit(debug::EXIT_FAILURE);
        }
        Err(e) => {
            hprintln!("oaep_encrypt_smoke: encrypt failed: {:?}", e);
            debug::exit(debug::EXIT_FAILURE);
        }
    }

    loop {}
}
