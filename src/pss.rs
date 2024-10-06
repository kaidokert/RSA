//! Support for the [Probabilistic Signature Scheme] (PSS) a.k.a. RSASSA-PSS.
//!
//! Designed by Mihir Bellare and Phillip Rogaway. Specified in [RFC8017 § 8.1].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pss-signatures).
//!
//! [Probabilistic Signature Scheme]: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
//! [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1

mod blinded_signing_key;
mod signature;
mod signing_key;
mod verifying_key;

pub use self::{
    blinded_signing_key::BlindedSigningKey, signature::Signature, signing_key::SigningKey,
    verifying_key::VerifyingKey,
};

use core::fmt::{self, Debug};
use core::marker::PhantomData;

use const_oid::AssociatedOid;
use digest::{Digest, DynDigest, FixedOutputReset};
use rand_core::CryptoRngCore;

use crate::algorithms::pad::{uint_to_be_pad, uint_to_zeroizing_be_pad};
use crate::algorithms::pss::*;
use crate::algorithms::rsa::{rsa_decrypt_and_check, rsa_encrypt};
use crate::errors::{Error, Result};
use crate::traits::PublicKeyParts;
use crate::traits::SignatureScheme;
use crate::traits::UnsignedModularInt;
use crate::{RsaPrivateKey, RsaPublicKey};

/// Digital signatures using PSS padding.
pub struct Pss {
    /// Create blinded signatures.
    pub blinded: bool,

    /// Digest type to use.
    pub digest: PhantomData<u8>,

    /// Salt length.
    pub salt_len: usize,
}

impl Pss {}

impl<T> SignatureScheme<T> for Pss
where
    T: UnsignedModularInt,
{
    // Sign

    fn verify(mut self, pub_key: &RsaPublicKey<T>, hashed: &[u8], sig: &[u8]) -> Result<()> {
        todo!()
    }
}

impl Debug for Pss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PSS")
            .field("blinded", &self.blinded)
            .field("digest", &"...")
            .field("salt_len", &self.salt_len)
            .finish()
    }
}

pub(crate) fn verify<T>(
    pub_key: &RsaPublicKey<T>,
    hashed: &[u8],
    sig: &T,
    sig_len: usize,
    digest: &mut dyn DynDigest,
    salt_len: usize,
) -> Result<()>
where
    T: UnsignedModularInt,
{
    if sig_len != pub_key.size() {
        return Err(Error::Verification);
    }
    todo!()
}

pub(crate) fn verify_digest<D, T>(
    pub_key: &RsaPublicKey<T>,
    hashed: &[u8],
    sig: &T,
    sig_len: usize,
    salt_len: usize,
) -> Result<()>
where
    D: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
    if sig >= pub_key.n() || sig_len != pub_key.size() {
        return Err(Error::Verification);
    }
    let encr = rsa_encrypt(pub_key, *sig);
    let mut cloned_t = (*sig).to_be_bytes();
    let storage = cloned_t.as_mut();
    let len = {
        let mut em = uint_to_be_pad(encr, pub_key.size(), storage)?;
        em.len()
    };
    let mut mutslice = storage.get_mut(..len).ok_or(Error::OutputBufferTooSmall)?;

    emsa_pss_verify_digest::<D>(hashed, mutslice, salt_len, pub_key.n().bits())
}

/// SignPSS calculates the signature of hashed using RSASSA-PSS.
///
/// Note that hashed must be the result of hashing the input message using the
/// given hash function. The opts argument may be nil, in which case sensible
/// defaults are used.
pub(crate) fn sign<T, R: CryptoRngCore>(
    rng: &mut R,
    blind: bool,
    priv_key: &RsaPrivateKey<T>,
    hashed: &[u8],
    salt_len: usize,
    digest: &mut dyn DynDigest,
) -> Result<()>
where
    T: UnsignedModularInt,
{
    todo!()
}

pub(crate) fn sign_digest<R: CryptoRngCore + ?Sized, D: Digest + FixedOutputReset, T>(
    rng: &mut R,
    blind: bool,
    priv_key: &RsaPrivateKey<T>,
    hashed: &[u8],
    salt_len: usize,
) -> Result<()>
where
    T: UnsignedModularInt,
{
    let _ = PhantomData::<D>;
    todo!()
}

/// signPSSWithSalt calculates the signature of hashed using PSS with specified salt.
///
/// Note that hashed must be the result of hashing the input message using the
/// given hash function. salt is a random sequence of bytes whose length will be
/// later used to verify the signature.
fn sign_pss_with_salt<T, R: CryptoRngCore>(
    blind_rng: Option<&mut R>,
    priv_key: &RsaPrivateKey<T>,
    hashed: &[u8],
    salt: &[u8],
    digest: &mut dyn DynDigest,
) -> Result<()>
where
    T: UnsignedModularInt,
{
    todo!()
}

fn sign_pss_with_salt_digest<R: CryptoRngCore + ?Sized, D: Digest + FixedOutputReset, T>(
    blind_rng: Option<&mut R>,
    priv_key: &RsaPrivateKey<T>,
    hashed: &[u8],
    salt: &[u8],
) -> Result<()>
where
    T: UnsignedModularInt,
{
    let _ = PhantomData::<D>;
    todo!()
}

fn get_pss_signature_algo_id<D>(salt_len: u8) -> Result<()>
where
    D: Digest + AssociatedOid,
{
    let _ = PhantomData::<D>;
    todo!()
}

#[cfg(test)]
mod test {
    use crate::pss::{BlindedSigningKey, Pss, Signature, SigningKey, VerifyingKey};
    use crate::{RsaPrivateKey, RsaPublicKey};

    use hex_literal::hex;
    use num_traits::{FromPrimitive, Num};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    use sha1::{Digest, Sha1};
    use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
    use signature::{DigestVerifier, Keypair, RandomizedDigestSigner, RandomizedSigner, Verifier};

    #[test]
    #[ignore]
    fn test_verify_pss() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_verify_pss_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_verify_pss_digest_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_and_verify_roundtrip() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_blinded_and_verify_roundtrip() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_and_verify_roundtrip_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_and_verify_roundtrip_blinded_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_and_verify_roundtrip_digest_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_and_verify_roundtrip_blinded_digest_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_verify_pss_hazmat() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_and_verify_pss_hazmat() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_and_verify_pss_blinded_hazmat() {
        todo!()
    }

    #[test]
    #[ignore]
    // Tests the corner case where the key is multiple of 8 + 1 bits long
    fn test_sign_and_verify_2049bit_key() {
        todo!()
    }
}
