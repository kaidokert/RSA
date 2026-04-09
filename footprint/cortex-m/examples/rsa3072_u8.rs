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
        "/../fixtures/rsa3072_sha256.rs"
    ));
}

#[entry]
fn main() -> ! {
    test_fixture_arg::<2048>(
        || {
            type U3072 = FixedUInt<u8, 384>;
            let key = public_key_from_be_bytes::<U3072>(
                &fixture::RSA3072_MODULUS,
                fixture::RSA3072_PUBLIC_EXPONENT,
            )
            .unwrap();
            let verifying_key = GenericVerifyingKey::<Sha256, _, _>::new(key);
            let signature = GenericSignature::from(U3072::from_be_bytes(&fixture::RSA3072_SIGNATURE));
            verifying_key
                .verify(fixture::RSA3072_MESSAGE, &signature)
                .is_ok()
        },
        "u8",
    );
    loop {}
}
