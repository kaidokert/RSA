#![no_main]
#![no_std]

use cortex_m_rt::entry;
use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
use rsa::signature::DigestVerifier;
use rsa_footprint_cortex_m::{test_fixture, MESSAGE, MODULUS, SIGNATURE};
use sha1::Sha1;

#[entry]
fn main() -> ! {
    test_fixture(
        || {
            type U512 = FixedUInt<u8, 64>;
            let key = public_key_from_be_bytes::<U512>(&MODULUS, 3).unwrap();
            let verifying_key = GenericVerifyingKey::<Sha1, _, _>::new(key);
            let signature = GenericSignature::from(U512::from_be_bytes(&SIGNATURE));
            verifying_key
                .verify_digest(
                    |digest: &mut Sha1| {
                        use sha1::Digest;
                        digest.update(MESSAGE);
                        Ok(())
                    },
                    &signature,
                )
                .is_ok()
        },
        "u8",
    );
    loop {}
}
