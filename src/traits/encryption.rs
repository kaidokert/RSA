//! Encryption-related traits.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use rand_core::{CryptoRng, TryCryptoRng};

use crate::errors::Result;

/// Encrypt the message using provided random source
pub trait RandomizedEncryptor {
    /// Encrypt the given message into caller-provided storage.
    fn encrypt_with_rng_into<'a, R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]>;

    /// Encrypt the given message.
    #[cfg(feature = "alloc")]
    fn encrypt_with_rng<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>>;
}

/// Decrypt the given message
pub trait Decryptor {
    /// Decrypt the given message.
    #[cfg(feature = "alloc")]
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Decrypt the given message using provided random source
pub trait RandomizedDecryptor {
    /// Decrypt the given message.
    #[cfg(feature = "alloc")]
    fn decrypt_with_rng<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Encryption keypair with an associated encryption key.
pub trait EncryptingKeypair {
    /// Encrypting key type for this keypair.
    type EncryptingKey: Clone;

    /// Get the encrypting key which can encrypt messages to be decrypted by
    /// the decryption key portion of this keypair.
    fn encrypting_key(&self) -> Self::EncryptingKey;
}
