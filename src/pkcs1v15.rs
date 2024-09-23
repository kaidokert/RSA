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

use core::fmt::Debug;
use core::marker::PhantomData;
use zeroize::{DefaultIsZeroes, Zeroizing};

use crate::algorithms::pad::{uint_to_be_pad, uint_to_zeroizing_be_pad};
use crate::algorithms::pkcs1v15::*;
use crate::algorithms::rsa::rsa_encrypt;
use crate::errors::{Error, Result};
use crate::key::{self, RsaPrivateKey, RsaPublicKey};
use crate::traits::{PaddingScheme, PublicKeyParts, SignatureScheme, UnsignedModularInt};

/// Encryption using PKCS#1 v1.5 padding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Pkcs1v15Encrypt;

impl PaddingScheme for Pkcs1v15Encrypt {}

/// `RSASSA-PKCS1-v1_5`: digital signatures using PKCS#1 v1.5 padding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs1v15Sign {
    /// Length of hash to use.
    pub hash_len: Option<usize>,

    /// Prefix.
    pub prefix: PhantomData<u8>,
}

impl Pkcs1v15Sign {
    /// Create new PKCS#1 v1.5 padding for the given digest.
    ///
    /// The digest must have an [`AssociatedOid`]. Make sure to enable the `oid`
    /// feature of the relevant digest crate.
    pub fn new<D>() -> Self {
        Self {
            hash_len: None,
            prefix: Default::default(),
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
fn encrypt<T>(pub_key: &RsaPublicKey<T>, msg: &[u8]) -> Result<()>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    key::check_public(pub_key)?;
    todo!()
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
    T: UnsignedModularInt + DefaultIsZeroes,
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
    T: UnsignedModularInt + DefaultIsZeroes,
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
    T: UnsignedModularInt + DefaultIsZeroes,
{
    let enn = pub_key.n();
    let pksize = pub_key.size();

    if sig >= pub_key.n() || sig_len != pub_key.size() {
        return Err(Error::Verification);
    }

    let encr = rsa_encrypt(pub_key, *sig);
    let mut storage = [0u8; 1024]; // todo
    let em = uint_to_be_pad(encr, pub_key.size(), &mut storage)?;
    pkcs1v15_sign_unpad(prefix, hashed, em, pub_key.size())
}

mod oid {}

#[cfg(test)]
mod tests {
    use super::*;
}
