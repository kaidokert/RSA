#![no_main]
#![no_std]

use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
use rsa::signature::Verifier;
use rsa_footprint_riscv::test_fixture;
use sha2::Sha256;

mod fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/rsa1536_sha256.rs"
    ));
}

#[riscv_rt::entry]
fn main() -> ! {
    test_fixture(
        || {
            type U1536 = FixedUInt<u8, 192>;
            let key = public_key_from_be_bytes::<U1536>(
                &fixture::RSA1536_MODULUS,
                fixture::RSA1536_PUBLIC_EXPONENT,
            )
            .unwrap();
            let verifying_key = GenericVerifyingKey::<Sha256, _, _>::new(key);
            let signature = GenericSignature::from(U1536::from_be_bytes(&fixture::RSA1536_SIGNATURE));
            verifying_key
                .verify(fixture::RSA1536_MESSAGE, &signature)
                .is_ok()
        },
        "u8",
    )
}
