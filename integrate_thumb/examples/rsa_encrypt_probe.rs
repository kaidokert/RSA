#![no_std]
#![no_main]

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use rsa::{BoxedUint, RsaPublicKey, rsa_encrypt};

#[cortex_m_rt::entry]
fn main() -> ! {
    let key = RsaPublicKey::new(BoxedUint::from(3233u64), BoxedUint::from(17u64)).unwrap();
    let msg = BoxedUint::from(42u64);

    let out = rsa_encrypt(&key, &msg).unwrap();
    assert_eq!(out, BoxedUint::from(2557u64));

    hprintln!("rsa_encrypt_probe ok");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
