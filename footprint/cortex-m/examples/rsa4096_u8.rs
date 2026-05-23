#![no_main]
#![no_std]

use cortex_m_rt::entry;
use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
use rsa::signature::Verifier;
use rsa_footprint_cortex_m::test_fixture_arg;
use sha2::Sha256;

mod fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa4096_sha256.rs"
    ));
}

#[entry]
fn main() -> ! {
    test_fixture_arg::<2048>(
        || {
            type U4096 = FixedUInt<u8, 512>;
            let key = public_key_from_be_bytes::<U4096>(
                &fixture::RSA4096_MODULUS,
                fixture::RSA4096_PUBLIC_EXPONENT,
            )
            .unwrap();
            let verifying_key = GenericVerifyingKey::<Sha256, _, _>::new(key);
            let signature = GenericSignature::from(U4096::from_be_bytes(&fixture::RSA4096_SIGNATURE));
            verifying_key
                .verify(fixture::RSA4096_MESSAGE, &signature)
                .is_ok()
        },
        "u8",
    );
    loop {}
}
