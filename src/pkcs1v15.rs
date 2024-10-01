//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

mod decrypting_key;
mod encrypting_key;
mod signature;
mod signing_key;
mod verifying_key;

pub use self::{
    decrypting_key::DecryptingKey, encrypting_key::EncryptingKey, signature::Signature,
    signing_key::SigningKey, verifying_key::VerifyingKey,
};

#[cfg(feature = "std")]
use std::println;

use const_oid::AssociatedOid;
use core::fmt::Debug;
use core::marker::PhantomData;
use digest::Digest;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::algorithms::pad::{uint_to_be_pad, uint_to_zeroizing_be_pad};
use crate::algorithms::pkcs1v15::*;
use crate::algorithms::rsa::{rsa_decrypt_and_check, rsa_encrypt};
use crate::errors::{Error, Result};
use crate::key::{self, RsaPrivateKey, RsaPublicKey};
use crate::traits::UnsignedModularInt;
use crate::traits::{PaddingScheme, PublicKeyParts, SignatureScheme};
use crate::Prefix;

/// Encryption using PKCS#1 v1.5 padding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Pkcs1v15Encrypt;

impl<T> PaddingScheme<T> for Pkcs1v15Encrypt
where
    T: UnsignedModularInt,
{
    // Decrypt

    fn encrypt<'a, Rng: CryptoRngCore>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey<T>,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        todo!()
    }
}

/// `RSASSA-PKCS1-v1_5`: digital signatures using PKCS#1 v1.5 padding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs1v15Sign {
    /// Length of hash to use.
    pub hash_len: Option<usize>,

    /// Prefix.
    pub prefix: Prefix,
}

impl Pkcs1v15Sign {
    /// Create new PKCS#1 v1.5 padding for the given digest.
    ///
    /// The digest must have an [`AssociatedOid`]. Make sure to enable the `oid`
    /// feature of the relevant digest crate.
    pub fn new<D>() -> Self
    where
        D: Digest + AssociatedOid,
    {
        Self {
            hash_len: Some(<D as Digest>::output_size()),
            prefix: pkcs1v15_generate_prefix::<D>(),
        }
    }

    /// Create new PKCS#1 v1.5 padding for computing an unprefixed signature.
    ///
    /// This sets `hash_len` to `None` and uses an empty `prefix`.
    pub fn new_unprefixed() -> Self {
        Self {
            hash_len: None,
            prefix: Default::default(),
        }
    }
}

impl<T> SignatureScheme<T> for Pkcs1v15Sign
where
    T: UnsignedModularInt,
{
    // Sign

    fn verify(self, pub_key: &RsaPublicKey<T>, hashed: &[u8], sig: &[u8]) -> Result<()> {
        if let Some(hash_len) = self.hash_len {
            if hashed.len() != hash_len {
                return Err(Error::InputNotHashed);
            }
        }

        todo!()
    }
}

/// Encrypts the given message with RSA and the padding
/// scheme from PKCS#1 v1.5.  The message must be no longer than the
/// length of the public modulus minus 11 bytes.
#[inline]
fn encrypt<'a, T, R: CryptoRngCore + ?Sized>(
    rng: &mut R,
    pub_key: &RsaPublicKey<T>,
    msg: &[u8],
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    T: UnsignedModularInt,
    <T as num_traits::FromBytes>::Bytes: num_traits::ops::bytes::NumBytes + Default,
{
    key::check_public(pub_key)?;

    let em = pkcs1v15_encrypt_pad(rng, msg, pub_key.size(), storage)?;
    let mut bytes = <T as num_traits::FromBytes>::Bytes::default();
    bytes.as_mut().copy_from_slice(em);
    storage.zeroize(); // Zero as soon as possible
    let mut padded_em = T::from_be_bytes(&bytes);
    bytes.as_mut().zeroize();
    let encr = rsa_encrypt(pub_key, padded_em);
    // zero out last copy
    padded_em.zeroize();
    uint_to_be_pad(encr, pub_key.size(), storage)
}

/// Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5.
///
/// If an `rng` is passed, it uses RSA blinding to avoid timing side-channel attacks.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key. See
/// `decrypt_session_key` for a way of solving this problem.
#[inline]
fn decrypt<T>(priv_key: &RsaPrivateKey<T>, ciphertext: &[u8]) -> Result<()>
where
    T: UnsignedModularInt,
{
    key::check_public(priv_key)?;
    todo!()
}

/// Calculates the signature of hashed using
/// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5. Note that `hashed` must
/// be the result of hashing the input message using the given hash
/// function. If hash is `None`, hashed is signed directly. This isn't
/// advisable except for interoperability.
///
/// If `rng` is not `None` then RSA blinding will be used to avoid timing
/// side-channel attacks.
///
/// This function is deterministic. Thus, if the set of possible
/// messages is small, an attacker may be able to build a map from
/// messages to signatures and identify the signed messages. As ever,
/// signatures provide authenticity, not confidentiality.
#[inline]
fn sign<T>(priv_key: &RsaPrivateKey<T>, prefix: &[u8], hashed: &[u8]) -> Result<()>
where
    T: UnsignedModularInt,
{
    todo!()
}

/// Verifies an RSA PKCS#1 v1.5 signature.
#[inline]
pub fn verify<T>(
    pub_key: &RsaPublicKey<T>,
    prefix: &[u8],
    hashed: &[u8],
    sig: &T,
    sig_len: usize,
) -> Result<()>
where
    T: UnsignedModularInt + core::fmt::Debug,
{
    let enn = pub_key.n();
    let pksize = pub_key.size();
    #[cfg(feature = "std")]
    println!(
        "enn: {:?}, pksize: {:?} sig_len: {:?}",
        enn, pksize, sig_len
    );
    if sig >= pub_key.n() {
        #[cfg(feature = "std")]
        println!("sig > pub_key.n()");
    }
    if sig_len != pub_key.size() {
        #[cfg(feature = "std")]
        println!("sig_len != pub_key.size()");
    }

    if sig >= pub_key.n() || sig_len != pub_key.size() {
        return Err(Error::Verification);
    }

    let encr = rsa_encrypt(pub_key, *sig);
    let mut storage = [0u8; 1024]; // todo
    let em = uint_to_be_pad(encr, pub_key.size(), &mut storage)?;
    pkcs1v15_sign_unpad(prefix, hashed, em, pub_key.size())
}

mod oid {
    use const_oid::ObjectIdentifier;

    /// A trait which associates an RSA-specific OID with a type.
    pub trait RsaSignatureAssociatedOid {
        /// The OID associated with this type.
        const OID: ObjectIdentifier;
    }

    #[cfg(feature = "sha1")]
    impl RsaSignatureAssociatedOid for sha1::Sha1 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
    }

    #[cfg(feature = "sha2")]
    impl RsaSignatureAssociatedOid for sha2::Sha224 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14");
    }

    #[cfg(feature = "sha2")]
    impl RsaSignatureAssociatedOid for sha2::Sha256 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    }

    #[cfg(feature = "sha2")]
    impl RsaSignatureAssociatedOid for sha2::Sha384 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    }

    #[cfg(feature = "sha2")]
    impl RsaSignatureAssociatedOid for sha2::Sha512 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    }
}

pub use oid::RsaSignatureAssociatedOid;

#[cfg(test)]
mod tests {
    use super::*;
    use ::signature::{
        hazmat::{PrehashSigner, PrehashVerifier},
        DigestSigner, DigestVerifier, Keypair, RandomizedDigestSigner, RandomizedSigner,
        SignatureEncoding, Signer, Verifier,
    };
    use hex_literal::hex;
    use num_bigint::BigUint;
    use num_traits::FromPrimitive;
    use num_traits::Num;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha8Rng,
    };
    use sha1::{Digest, Sha1};
    use sha2::Sha256;
    use sha3::Sha3_256;

    use crate::traits::{
        Decryptor, EncryptingKeypair, PublicKeyParts, RandomizedDecryptor, RandomizedEncryptor,
    };
    use crate::{RsaPrivateKey, RsaPublicKey};

    #[test]
    #[ignore]
    fn test_decrypt_pkcs1v15() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_encrypt_decrypt_pkcs1v15() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_decrypt_pkcs1v15_traits() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_encrypt_decrypt_pkcs1v15_traits() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_pkcs1v15() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_pkcs1v15_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_pkcs1v15_signer_sha2_256() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_pkcs1v15_signer_sha3_256() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_sign_pkcs1v15_digest_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_verify_pkcs1v15() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_verify_pkcs1v15_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_verify_pkcs1v15_digest_signer() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_unpadded_signature() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_unpadded_signature_hazmat() {
        todo!()
    }
}
