//! Supported padding schemes.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use rand_core::TryCryptoRng;

use crate::errors::Result;
#[cfg(feature = "full")]
use crate::key::{RsaPrivateKey, RsaPublicKey};
#[cfg(not(feature = "full"))]
use crate::key::RsaPublicKey;

/// Padding scheme used for encryption.
pub trait PaddingScheme {
    /// Decrypt the given message using the given private key.
    ///
    /// If an `rng` is passed, it uses RSA blinding to help mitigate timing
    /// side-channel attacks.
    #[cfg(feature="full")]
    fn decrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    /// Encrypt the given message using the given public key.
    #[cfg(feature="alloc")]
    fn encrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Digital signature scheme.
pub trait SignatureScheme {
    /// Sign the given digest.
    #[cfg(feature="full")]
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
    fn verify(self, pub_key: &RsaPublicKey, hashed: &[u8], sig: &[u8]) -> Result<()>;
}
