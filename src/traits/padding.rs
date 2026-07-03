//! Supported padding schemes.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use rand_core::TryCryptoRng;

use crate::errors::Result;
#[cfg(feature = "private-key")]
use crate::key::RsaPrivateKey;
use crate::traits::modular::CtModulusParams;
use crate::traits::{PublicKeyParts, UnsignedModularInt};

/// Padding scheme used for encryption.
pub trait PaddingScheme {
    /// Decrypt the given message using the given private key.
    ///
    /// If an `rng` is passed, it uses RSA blinding to help mitigate timing
    /// side-channel attacks.
    #[cfg(feature = "private-key")]
    fn decrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    /// Encrypt the given message using the given public key.
    ///
    /// Bound `K::MontyParams: CtModulusParams` — `NctPublicKey`-derived
    /// keys can't reach this entry point, matching the
    /// [`crate::traits::RandomizedEncryptor`] gate on
    /// `GenericEncryptingKey`.
    #[cfg(feature = "alloc")]
    fn encrypt<Rng, K, T>(self, rng: &mut Rng, pub_key: &K, msg: &[u8]) -> Result<Vec<u8>>
    where
        Rng: TryCryptoRng + ?Sized,
        T: UnsignedModularInt,
        K: PublicKeyParts<T>,
        K::MontyParams: CtModulusParams;
}

/// Digital signature scheme.
pub trait SignatureScheme {
    /// Sign the given digest.
    #[cfg(feature = "private-key")]
    fn sign<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        hashed: &[u8],
    ) -> Result<Vec<u8>>;

    /// Verify a signed message.
    ///
    /// `hashed` must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    ///
    /// If the message is valid `Ok(())` is returned, otherwise an `Err` indicating failure.
    fn verify<K, T>(self, pub_key: &K, hashed: &[u8], sig: &[u8]) -> Result<()>
    where
        T: UnsignedModularInt,
        K: PublicKeyParts<T>;
}
