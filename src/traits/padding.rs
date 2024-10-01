//! Supported padding schemes.
use rand_core::CryptoRngCore;

use crate::errors::Result;
use crate::key::{RsaPrivateKey, RsaPublicKey};

use super::UnsignedModularInt;

/// Padding scheme used for encryption.
pub trait PaddingScheme<T>
where
    T: UnsignedModularInt,
{
    /// Decrypt the given message using the given private key.
    ///
    /// If an `rng` is passed, it uses RSA blinding to help mitigate timing
    /// side-channel attacks.

    // Decrypt function

    /// Encrypt the given message using the given public key.
    fn encrypt<'a, Rng: CryptoRngCore>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey<T>,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]>;
}

/// Digital signature scheme.
pub trait SignatureScheme<T>
where
    T: UnsignedModularInt + Clone,
{
    /// Sign the given digest.

    // Sign function

    /// Verify a signed message.
    ///
    /// `hashed` must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    ///
    /// If the message is valid `Ok(())` is returned, otherwise an `Err` indicating failure.
    fn verify(self, pub_key: &RsaPublicKey<T>, hashed: &[u8], sig: &[u8]) -> Result<()>;
}
