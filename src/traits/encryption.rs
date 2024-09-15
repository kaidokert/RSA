//! Encryption-related traits.

use crate::errors::Result;

/// Encrypt the message using provided random source
pub trait RandomizedEncryptor {}

/// Decrypt the given message
pub trait Decryptor {}

/// Decrypt the given message using provided random source
pub trait RandomizedDecryptor {}

/// Encryption keypair with an associated encryption key.
pub trait EncryptingKeypair {
    /// Encrypting key type for this keypair.
    type EncryptingKey: Clone;

    /// Get the encrypting key which can encrypt messages to be decrypted by
    /// the decryption key portion of this keypair.
    fn encrypting_key(&self) -> Self::EncryptingKey;
}
