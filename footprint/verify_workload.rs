// RSA-local feature matrix and PKCS#1 v1.5 verification workload.
//
// Target examples select a supported matrix and retain ownership of their
// entry point, measurement adapter, reporter, and terminal behavior.

macro_rules! define_rsa_verify_workload {
    (full) => {
        const _: () = {
            const N: usize = cfg!(feature = "key_512") as usize
                + cfg!(feature = "key_768") as usize
                + cfg!(feature = "key_1024") as usize
                + cfg!(feature = "key_1536") as usize
                + cfg!(feature = "key_2048") as usize
                + cfg!(feature = "key_3072") as usize
                + cfg!(feature = "key_4096") as usize;
            assert!(N == 1, "exactly one `key_*` feature must be enabled");
        };
        const _: () = {
            const N: usize =
                cfg!(feature = "limb_u8") as usize + cfg!(feature = "limb_u32") as usize;
            assert!(N == 1, "exactly one `limb_*` feature must be enabled");
        };

        #[cfg(all(feature = "key_512", feature = "limb_u8"))]
        type Key = fixed_bigint::FixedUInt<u8, 64>;
        #[cfg(all(feature = "key_512", feature = "limb_u32"))]
        type Key = fixed_bigint::FixedUInt<u32, 16>;
        #[cfg(all(feature = "key_768", feature = "limb_u8"))]
        type Key = fixed_bigint::FixedUInt<u8, 96>;
        #[cfg(all(feature = "key_768", feature = "limb_u32"))]
        type Key = fixed_bigint::FixedUInt<u32, 24>;
        #[cfg(all(feature = "key_1024", feature = "limb_u8"))]
        type Key = fixed_bigint::FixedUInt<u8, 128>;
        #[cfg(all(feature = "key_1024", feature = "limb_u32"))]
        type Key = fixed_bigint::FixedUInt<u32, 32>;
        #[cfg(all(feature = "key_1536", feature = "limb_u8"))]
        type Key = fixed_bigint::FixedUInt<u8, 192>;
        #[cfg(all(feature = "key_1536", feature = "limb_u32"))]
        type Key = fixed_bigint::FixedUInt<u32, 48>;
        #[cfg(all(feature = "key_2048", feature = "limb_u8"))]
        type Key = fixed_bigint::FixedUInt<u8, 256>;
        #[cfg(all(feature = "key_2048", feature = "limb_u32"))]
        type Key = fixed_bigint::FixedUInt<u32, 64>;
        #[cfg(all(feature = "key_3072", feature = "limb_u8"))]
        type Key = fixed_bigint::FixedUInt<u8, 384>;
        #[cfg(all(feature = "key_3072", feature = "limb_u32"))]
        type Key = fixed_bigint::FixedUInt<u32, 96>;
        #[cfg(all(feature = "key_4096", feature = "limb_u8"))]
        type Key = fixed_bigint::FixedUInt<u8, 512>;
        #[cfg(all(feature = "key_4096", feature = "limb_u32"))]
        type Key = fixed_bigint::FixedUInt<u32, 128>;

        #[cfg(feature = "limb_u8")]
        const BACKEND: &str = "u8";
        #[cfg(feature = "limb_u32")]
        const BACKEND: &str = "u32";
    };
    (avr) => {
        const _: () = {
            const N: usize = cfg!(feature = "key_512") as usize
                + cfg!(feature = "key_768") as usize
                + cfg!(feature = "key_1024") as usize
                + cfg!(feature = "key_1536") as usize;
            assert!(N == 1, "exactly one `key_*` feature must be enabled");
        };

        #[cfg(feature = "key_512")]
        type Key = fixed_bigint::FixedUInt<u8, 64>;
        #[cfg(feature = "key_768")]
        type Key = fixed_bigint::FixedUInt<u8, 96>;
        #[cfg(feature = "key_1024")]
        type Key = fixed_bigint::FixedUInt<u8, 128>;
        #[cfg(feature = "key_1536")]
        type Key = fixed_bigint::FixedUInt<u8, 192>;

    };
}

macro_rules! define_rsa_verify_fixtures {
    (full) => {
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
    };
    (avr) => {
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
        }
    };
}

macro_rules! define_rsa_verify_operation {
    () => {
        const _: () = {
            const N: usize = cfg!(feature = "hash_sha1") as usize
                + cfg!(feature = "hash_sha256") as usize;
            assert!(N == 1, "exactly one `hash_*` feature must be enabled");
        };
        #[cfg(all(feature = "hash_sha1", not(feature = "key_512")))]
        compile_error!("hash_sha1 only paired with key_512 (no fixture exists for other key sizes)");

        #[cfg(feature = "hash_sha1")]
        type Hash = sha1::Sha1;
        #[cfg(feature = "hash_sha256")]
        type Hash = sha2::Sha256;

        fn verify_fixture() -> bool {
            use rsa::signature::Verifier as _;

            let key = rsa::modmath_support::public_key_from_be_bytes::<Key>(
                &fixture::MODULUS,
                fixture::PUBLIC_EXPONENT,
            )
            .unwrap();
            let verifying_key = rsa::pkcs1v15::GenericVerifyingKey::<Hash, _, _>::new(key);
            let signature =
                rsa::pkcs1v15::GenericSignature::from(Key::from_be_bytes(&fixture::SIGNATURE));
            verifying_key.verify(fixture::MESSAGE, &signature).is_ok()
        }
    };
}
