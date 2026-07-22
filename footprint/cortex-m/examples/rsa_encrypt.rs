#![no_std]
#![no_main]

use core::convert::Infallible;

use cortex_m_semihosting::{debug, hprintln};
use fixed_bigint::FixedUInt;
use panic_semihosting as _;
use rsa::{
    modmath_support::public_key_from_be_bytes,
    pkcs1v15::GenericEncryptingKey,
    rand_core::{TryCryptoRng, TryRng},
    traits::RandomizedEncryptor,
};

const MODULUS: [u8; 64] = [
    0x96, 0x9d, 0x03, 0xff, 0xa9, 0x8d, 0x88, 0x8f, 0x3a, 0xa4, 0xf2, 0xfe, 0xd2, 0x32, 0xe6, 0x1c,
    0x4a, 0xcf, 0x06, 0x63, 0xa9, 0x2f, 0x99, 0x03, 0x4c, 0xf7, 0xb7, 0x24, 0x5a, 0x1a, 0x1e, 0x5e,
    0xaf, 0xa5, 0x65, 0xaf, 0xb9, 0x0b, 0xab, 0x22, 0x85, 0x71, 0x2f, 0xaa, 0x50, 0x39, 0x39, 0xa0,
    0x65, 0xfb, 0x60, 0xdd, 0x08, 0x28, 0xa3, 0x84, 0xf2, 0x6d, 0x8a, 0xfc, 0x28, 0x6d, 0xf6, 0xcf,
];

const EXPECTED_CIPHERTEXT: [u8; 64] = [
    0x5a, 0xf8, 0xde, 0x1e, 0x0b, 0x93, 0x02, 0xb8, 0x73, 0x0c, 0xe7, 0xd7, 0x1a, 0x0c, 0xff, 0x11,
    0xee, 0xb9, 0x3a, 0x7e, 0x12, 0x5f, 0x40, 0xdd, 0x03, 0x49, 0x4d, 0xf4, 0x46, 0x5c, 0x72, 0x04,
    0x83, 0x56, 0xb0, 0x2d, 0xa3, 0x10, 0x36, 0x58, 0xa7, 0x41, 0x4c, 0x42, 0x6d, 0x12, 0x66, 0x03,
    0x27, 0x9b, 0x20, 0x7e, 0x81, 0xf2, 0x23, 0x33, 0x39, 0x1e, 0xb9, 0xb7, 0x99, 0x07, 0xc1, 0x74,
];

struct CounterRng {
    next: u8,
}

impl CounterRng {
    const fn new() -> Self {
        Self { next: 1 }
    }

    fn next_byte(&mut self) -> u8 {
        let byte = self.next;
        self.next = self.next.wrapping_add(1);
        if self.next == 0 {
            self.next = 1;
        }
        byte
    }
}

impl TryRng for CounterRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest {
            *byte = self.next_byte();
        }
        Ok(())
    }
}

impl TryCryptoRng for CounterRng {}

#[cortex_m_rt::entry]
fn main() -> ! {
    match run() {
        Ok(()) => {
            debug::exit(debug::EXIT_SUCCESS);
            loop {}
        }
        Err(err) => {
            hprintln!("rsa_encrypt failed: {:?}", err);
            debug::exit(debug::EXIT_FAILURE);
            loop {}
        }
    }
}

fn run() -> rsa::Result<()> {
    type U512 = FixedUInt<u8, 64>;

    let key = GenericEncryptingKey::new(public_key_from_be_bytes::<U512>(&MODULUS, 3)?);
    let mut rng = CounterRng::new();
    let mut storage = [0u8; 64];
    let ciphertext = key.encrypt_with_rng_into(&mut rng, b"hello world!", &mut storage)?;
    if ciphertext != EXPECTED_CIPHERTEXT {
        return Err(rsa::Error::Verification);
    }

    hprintln!("rsa_encrypt: ok");
    Ok(())
}
