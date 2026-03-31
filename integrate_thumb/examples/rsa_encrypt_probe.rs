#![no_std]
#![no_main]

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::{rsa_encrypt, ModMathFixedUint};

#[cortex_m_rt::entry]
fn main() -> ! {
    run().unwrap();
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

fn run() -> rsa::Result<()> {
    let key = public_key_from_be_bytes(&[0x0c, 0xa1], 17)?;
    let msg = ModMathFixedUint::<2>::from_be_slice(&[0x00, 0x2a]);

    let out = rsa_encrypt(&key, &msg)?;
    assert_eq!(out, ModMathFixedUint::<2>::from_be_slice(&[0x09, 0xfd]));

    hprintln!("rsa_encrypt_probe ok");
    Ok(())
}
