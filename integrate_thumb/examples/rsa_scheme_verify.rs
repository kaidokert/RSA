#![no_std]
#![no_main]

use panic_semihosting as _;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::traits::SignatureScheme;
use rsa::{BoxedUint, RsaPublicKey};
use sha1::Sha1;

#[cortex_m_rt::entry]
fn main() -> ! {
    let key = RsaPublicKey::new(BoxedUint::from(3233u64), BoxedUint::from(17u64)).unwrap();
    let hashed = [0u8; 20];
    let sig = [0u8; 2];

    loop {
        let _ = Pkcs1v15Sign::new::<Sha1>().verify(&key, &hashed, &sig);
    }
}
