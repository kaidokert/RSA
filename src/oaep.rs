//! Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#oaep-encryption).

mod encrypting_key;

pub use self::encrypting_key::EncryptingKey;

use core::fmt;
use core::marker::PhantomData;

use digest::{Digest, DynDigest, FixedOutputReset};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::algorithms::oaep::*;
use crate::algorithms::pad::{uint_to_be_pad, uint_to_zeroizing_be_pad};
use crate::algorithms::rsa::{rsa_decrypt_and_check, rsa_encrypt};
use crate::errors::{Error, Result};
use crate::key::{self, RsaPrivateKey, RsaPublicKey};
use crate::traits::{PaddingScheme, PublicKeyParts, UnsignedModularInt};

use heapless::String;

/// Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
///
/// - `digest` is used to hash the label. The maximum possible plaintext length is `m = k - 2 * h_len - 2`,
///   where `k` is the size of the RSA modulus.
/// - `mgf_digest` specifies the hash function that is used in the [MGF1](https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2).
/// - `label` is optional data that can be associated with the message.
///
/// The two hash functions can, but don't need to be the same.
///
/// A prominent example is the [`AndroidKeyStore`](https://developer.android.com/guide/topics/security/cryptography#oaep-mgf1-digest).
/// It uses SHA-1 for `mgf_digest` and a user-chosen SHA flavour for `digest`.
pub struct Oaep {
    /// Digest type to use.
    pub digest: PhantomData<u8>, // Box<dyn DynDigest + Send + Sync>,

    /// Digest to use for Mask Generation Function (MGF).
    pub mgf_digest: PhantomData<u8>, //Box<dyn DynDigest + Send + Sync>,

    /// Optional label.
    pub label: Option<String<128>>,
}

impl Oaep {
    /// Create a new OAEP `PaddingScheme`, using `T` as the hash function for both the default (empty) label and for MGF1.
    ///
    pub fn new<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        Self {
            digest: Default::default(),     //Box::new(T::new()),
            mgf_digest: Default::default(), //Box::new(T::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme` with an associated `label`, using `T` as the hash function for both the label and for MGF1.
    pub fn new_with_label<T: 'static + Digest + DynDigest + Send + Sync, S: AsRef<str>>(
        label: S,
    ) -> Self {
        Self {
            digest: Default::default(),     // Box::new(T::new()),
            mgf_digest: Default::default(), //Box::new(T::new()),
            label: None,                    // Some(label.as_ref().to_string()),
        }
    }

    /// Create a new OAEP `PaddingScheme`, using `T` as the hash function for the default (empty) label, and `U` as the hash function for MGF1.
    /// If a label is needed use `PaddingScheme::new_oaep_with_label` or `PaddingScheme::new_oaep_with_mgf_hash_with_label`.
    ///
    pub fn new_with_mgf_hash<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
    >() -> Self {
        Self {
            digest: Default::default(),     // Box::new(T::new()),
            mgf_digest: Default::default(), // Box::new(U::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme` with an associated `label`, using `T` as the hash function for the label, and `U` as the hash function for MGF1.
    pub fn new_with_mgf_hash_and_label<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
        S: AsRef<str>,
    >(
        label: S,
    ) -> Self {
        Self {
            digest: Default::default(),     // Box::new(T::new()),
            mgf_digest: Default::default(), // Box::new(U::new()),
            label: None,                    //Some(label.as_ref().to_string()),
        }
    }
}

impl<T> PaddingScheme<T> for Oaep
where
    T: UnsignedModularInt,
{
    fn encrypt<'a, Rng: CryptoRngCore>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey<T>,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        todo!()
        /*
        encrypt(
            rng,
            pub_key,
            msg,
            &mut *self.digest,
            &mut *self.mgf_digest,
            self.label,
            storage,
        )
         */
    }
}

impl fmt::Debug for Oaep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAEP")
            .field("digest", &"...")
            .field("mgf_digest", &"...")
            .field("label", &self.label)
            .finish()
    }
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
fn encrypt<'a, T, R: CryptoRngCore + ?Sized>(
    rng: &mut R,
    pub_key: &RsaPublicKey<T>,
    msg: &[u8],
    digest: &mut dyn DynDigest,
    mgf_digest: &mut dyn DynDigest,
    label: Option<String<128>>,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    T: UnsignedModularInt,
{
    key::check_public(pub_key)?;

    let em = oaep_encrypt(rng, msg, digest, mgf_digest, label, pub_key.size(), storage)?;

    todo!()
    //let int = Zeroizing::new(BigUint::from_bytes_be(&em));
    //uint_to_be_pad(rsa_encrypt(pub_key, &int)?, pub_key.size())
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
fn encrypt_digest<'a, T, R: CryptoRngCore + ?Sized, D: Digest, MGD: Digest + FixedOutputReset>(
    rng: &mut R,
    pub_key: &RsaPublicKey<T>,
    msg: &[u8],
    label: Option<String<128>>,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    T: UnsignedModularInt,
{
    key::check_public(pub_key)?;

    let em = oaep_encrypt_digest::<_, D, MGD>(rng, msg, label, pub_key.size(), storage)?;

    todo!()
    //let int = Zeroizing::new(BigUint::from_bytes_be(&em));
    //uint_to_be_pad(rsa_encrypt(pub_key, &int)?, pub_key.size())
}

#[cfg(test)]
mod tests {
    use crate::key::{RsaPrivateKey, RsaPublicKey};
}
