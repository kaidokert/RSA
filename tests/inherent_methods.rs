//! Round trips through the per-algorithm inherent methods on `PublicKey` and
//! `PrivateKey`, which upstream exercises only from doc examples.
#![cfg(feature = "encoding")]

use pkcs8::DecodePrivateKey;
use rand::rngs::ChaCha8Rng;
use rand_core::SeedableRng;
use rsa::{Error, PrivateKey, PublicKey};
use sha2::{Digest, Sha256};

fn keys() -> (PrivateKey, PublicKey) {
    let private_key = PrivateKey::from_pkcs8_der(include_bytes!("examples/pkcs8/rsa2048-priv.der"))
        .expect("valid fixture");
    let public_key = private_key.to_public_key();
    (private_key, public_key)
}

#[test]
fn oaep_round_trip() {
    let (private_key, public_key) = keys();
    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    let msg = b"inherent oaep";

    let ct = public_key
        .oaep_encrypt_with_rng::<Sha256, _>(&mut rng, msg)
        .unwrap();
    assert_eq!(private_key.oaep_decrypt::<Sha256>(&ct).unwrap(), msg);
    assert_eq!(
        private_key
            .oaep_decrypt_with_rng::<Sha256, _>(&mut rng, &ct)
            .unwrap(),
        msg
    );

    #[cfg(feature = "getrandom")]
    {
        let ct = public_key.oaep_encrypt::<Sha256>(msg).unwrap();
        assert_eq!(private_key.oaep_decrypt::<Sha256>(&ct).unwrap(), msg);
    }
}

#[test]
fn pss_round_trip() {
    let (private_key, public_key) = keys();
    let mut rng = ChaCha8Rng::from_seed([2; 32]);
    let msg = b"inherent pss";
    let hash = Sha256::digest(msg);

    let sig = private_key
        .pss_sign_with_rng::<Sha256, _>(&mut rng, msg)
        .unwrap();
    public_key.pss_verify::<Sha256>(msg, &sig).unwrap();
    public_key
        .pss_verify_prehash::<Sha256>(&hash, &sig)
        .unwrap();

    let sig = private_key
        .pss_sign_prehash_with_rng::<Sha256, _>(&mut rng, &hash)
        .unwrap();
    public_key.pss_verify::<Sha256>(msg, &sig).unwrap();
    assert_eq!(
        public_key.pss_verify::<Sha256>(b"other message", &sig),
        Err(Error::Verification)
    );
    assert!(
        public_key
            .pss_verify_prehash::<Sha256>(&hash[1..], &sig)
            .is_err()
    );

    #[cfg(feature = "getrandom")]
    {
        let sig = private_key.pss_sign::<Sha256>(msg).unwrap();
        public_key.pss_verify::<Sha256>(msg, &sig).unwrap();
        let sig = private_key.pss_sign_prehash::<Sha256>(&hash).unwrap();
        public_key
            .pss_verify_prehash::<Sha256>(&hash, &sig)
            .unwrap();
    }
}

#[cfg(feature = "pkcs1v15")]
#[test]
fn pkcs1v15_round_trip() {
    let (private_key, public_key) = keys();
    let mut rng = ChaCha8Rng::from_seed([3; 32]);
    let msg = b"inherent pkcs1v15";
    let hash = Sha256::digest(msg);

    let ct = public_key.pkcs1v15_encrypt_with_rng(&mut rng, msg).unwrap();
    assert_eq!(private_key.pkcs1v15_decrypt(&ct).unwrap(), msg);
    assert_eq!(
        private_key
            .pkcs1v15_decrypt_with_rng(&mut rng, &ct)
            .unwrap(),
        msg
    );

    let sig = private_key.pkcs1v15_sign::<Sha256>(msg).unwrap();
    public_key.pkcs1v15_verify::<Sha256>(msg, &sig).unwrap();
    assert_eq!(
        private_key.pkcs1v15_sign_prehash::<Sha256>(&hash).unwrap(),
        sig
    );
    assert_eq!(
        private_key
            .pkcs1v15_sign_with_rng::<Sha256, _>(&mut rng, msg)
            .unwrap(),
        sig
    );
    assert_eq!(
        private_key
            .pkcs1v15_sign_prehash_with_rng::<Sha256, _>(&mut rng, &hash)
            .unwrap(),
        sig
    );
    public_key
        .pkcs1v15_verify_prehash::<Sha256>(&hash, &sig)
        .unwrap();
    assert_eq!(
        public_key.pkcs1v15_verify_prehash::<Sha256>(&hash[1..], &sig),
        Err(Error::InputNotHashed)
    );
    assert_eq!(
        public_key.pkcs1v15_verify::<Sha256>(b"other message", &sig),
        Err(Error::Verification)
    );

    #[cfg(feature = "getrandom")]
    {
        let ct = public_key.pkcs1v15_encrypt(msg).unwrap();
        assert_eq!(private_key.pkcs1v15_decrypt(&ct).unwrap(), msg);
    }
}
