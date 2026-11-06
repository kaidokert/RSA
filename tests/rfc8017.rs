//! Regression tests for RFC8017 signature representation and verification boundaries.
#![cfg(feature = "keygen")]

use rand::{rngs::ChaCha8Rng, SeedableRng};
use rsa::{
    pss,
    signature::{hazmat::PrehashVerifier, DigestVerifier, Verifier},
    traits::PublicKeyParts,
    BoxedUint, Pss, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

fn private_key() -> RsaPrivateKey {
    // 1025 bits makes both k != storage width and PSS emLen != k.
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    RsaPrivateKey::new(&mut rng, 1025).unwrap()
}

fn check_pss(key: &RsaPublicKey, message: &[u8], bytes: &[u8], valid: bool) {
    let digest = Sha256::digest(message);
    let signature = pss::Signature::try_from(bytes).unwrap();
    let verifier = pss::VerifyingKey::<Sha256>::new(key.clone());
    assert_eq!(
        key.verify(Pss::<Sha256>::new(), &digest, bytes).is_ok(),
        valid
    );
    assert_eq!(verifier.verify(message, &signature).is_ok(), valid);
    assert_eq!(verifier.verify_prehash(&digest, &signature).is_ok(), valid);
    assert_eq!(
        verifier
            .verify_digest(
                |d| {
                    d.update(message);
                    Ok(())
                },
                &signature
            )
            .is_ok(),
        valid
    );
    assert_eq!(
        pss::VerifyingKey::<Sha256>::new_with_auto_salt_len(key.clone())
            .verify(message, &signature)
            .is_ok(),
        valid
    );
}

#[test]
fn pss_rejects_out_of_range_signature_alias() {
    const OUT_OF_RANGE: &[u8] = b"out-of-range signature representative";

    let key = private_key();
    let public = key.to_public_key();
    let digest = Sha256::digest(OUT_OF_RANGE);
    let mut rng = ChaCha8Rng::from_seed([7; 32]);
    let bytes = key
        .sign_with_rng(&mut rng, Pss::<Sha256>::new(), &digest)
        .unwrap();

    let s = BoxedUint::from_be_slice(&bytes, public.n_bits_precision()).unwrap();
    let alias = s.wrapping_add(public.n().as_ref());
    assert!(alias >= *public.n().as_ref());

    // The 1025-bit modulus leaves enough space for s+n in the 129-octet signature.
    let bytes = alias.to_be_bytes();
    let bytes = &bytes[bytes.len() - public.size()..];
    check_pss(&public, OUT_OF_RANGE, bytes, false);
}
