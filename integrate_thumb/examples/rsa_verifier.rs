#![no_std]
#![no_main]

use panic_semihosting as _;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BoxedUint, RsaPublicKey};
use sha1::Sha1;

#[cortex_m_rt::entry]
fn main() -> ! {
    let key = RsaPublicKey::new(BoxedUint::from(3233u64), BoxedUint::from(17u64)).unwrap();
    let verifying_key = VerifyingKey::<Sha1>::new(key);
    let signature = Signature::try_from([0u8; 2].as_slice()).unwrap();

    loop {
        let _ = verifying_key.verify(b"x", &signature);
    }
}
