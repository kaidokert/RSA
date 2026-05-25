use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;

mod fixture {
    include!("../footprint/fixtures/rsa2048_sha256.rs");
}

fn main() {
    type U2048 = FixedUInt<u32, 64>;

    let key = public_key_from_be_bytes::<U2048>(&fixture::MODULUS, fixture::PUBLIC_EXPONENT)
        .expect("public key");
    let verifying_key = GenericVerifyingKey::<Sha256, _, _>::new(key);
    let signature = GenericSignature::from(rsa::ModMathValue::from_inner(U2048::from_be_bytes(
        &fixture::SIGNATURE,
    )));

    verifying_key
        .verify(fixture::MESSAGE, &signature)
        .expect("pkcs1v15 verify");

    println!("rsa2048 verify: ok");
}
