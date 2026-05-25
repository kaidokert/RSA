//! Unified PKCS#1 v1.5 verify example for all (key-size × limb-size) combinations
//! we measure. Picks the fixture and `FixedUInt` type from cfg features so the
//! same source file builds for every entry in the suite.
//!
//! Exactly one `key_*` feature and exactly one `limb_*` feature must be enabled.

#![no_main]
#![no_std]

use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_from_be_bytes;
use rsa::pkcs1v15::{GenericSignature, GenericVerifyingKey};
use rsa::signature::Verifier;
use rsa_footprint_riscv::test_fixture;

#[cfg(feature = "hash_sha1")]
type Hash = sha1::Sha1;
#[cfg(feature = "hash_sha256")]
type Hash = sha2::Sha256;

mod fixture {
    #[cfg(all(feature = "key_512", feature = "hash_sha1"))]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/rsa512_sha1.rs"));
    #[cfg(all(feature = "key_512", feature = "hash_sha256"))]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/rsa512_sha256.rs"));
    #[cfg(feature = "key_768")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/rsa768_sha256.rs"));
    #[cfg(feature = "key_1024")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/rsa1024_sha256.rs"));
    #[cfg(feature = "key_1536")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/rsa1536_sha256.rs"));
    #[cfg(feature = "key_2048")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/rsa2048_sha256.rs"));
    #[cfg(feature = "key_3072")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/rsa3072_sha256.rs"));
    #[cfg(feature = "key_4096")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/rsa4096_sha256.rs"));
}

#[cfg(all(feature = "key_512", feature = "limb_u8"))]
type Key = FixedUInt<u8, 64>;
#[cfg(all(feature = "key_512", feature = "limb_u32"))]
type Key = FixedUInt<u32, 16>;
#[cfg(all(feature = "key_768", feature = "limb_u8"))]
type Key = FixedUInt<u8, 96>;
#[cfg(all(feature = "key_768", feature = "limb_u32"))]
type Key = FixedUInt<u32, 24>;
#[cfg(all(feature = "key_1024", feature = "limb_u8"))]
type Key = FixedUInt<u8, 128>;
#[cfg(all(feature = "key_1024", feature = "limb_u32"))]
type Key = FixedUInt<u32, 32>;
#[cfg(all(feature = "key_1536", feature = "limb_u8"))]
type Key = FixedUInt<u8, 192>;
#[cfg(all(feature = "key_1536", feature = "limb_u32"))]
type Key = FixedUInt<u32, 48>;
#[cfg(all(feature = "key_2048", feature = "limb_u8"))]
type Key = FixedUInt<u8, 256>;
#[cfg(all(feature = "key_2048", feature = "limb_u32"))]
type Key = FixedUInt<u32, 64>;
#[cfg(all(feature = "key_3072", feature = "limb_u8"))]
type Key = FixedUInt<u8, 384>;
#[cfg(all(feature = "key_3072", feature = "limb_u32"))]
type Key = FixedUInt<u32, 96>;
#[cfg(all(feature = "key_4096", feature = "limb_u8"))]
type Key = FixedUInt<u8, 512>;
#[cfg(all(feature = "key_4096", feature = "limb_u32"))]
type Key = FixedUInt<u32, 128>;

#[cfg(feature = "limb_u8")]
const BACKEND: &str = "u8";
#[cfg(feature = "limb_u32")]
const BACKEND: &str = "u32";

#[riscv_rt::entry]
fn main() -> ! {
    test_fixture(
        || {
            let key = public_key_from_be_bytes::<Key>(
                &fixture::MODULUS,
                fixture::PUBLIC_EXPONENT,
            )
            .unwrap();
            let verifying_key = GenericVerifyingKey::<Hash, _, _>::new(key);
            let signature = GenericSignature::from(Key::from_be_bytes(&fixture::SIGNATURE));
            verifying_key
                .verify(fixture::MESSAGE, &signature)
                .is_ok()
        },
        BACKEND,
    )
}
