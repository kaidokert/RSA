use super::{decrypt, EncryptingKey};
use crate::traits::UnsignedModularInt;
use crate::{
    key::RsaPrivateKey,
    traits::{Decryptor, EncryptingKeypair, RandomizedDecryptor},
    Result,
};
use zeroize::DefaultIsZeroes;
use zeroize::ZeroizeOnDrop;

/// Decryption key for PKCS#1 v1.5 decryption as described in [RFC8017 § 7.2].
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
pub struct DecryptingKey<T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    inner: RsaPrivateKey<T>,
}

impl<T> DecryptingKey<T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPrivateKey<T>) -> Self {
        Self { inner: key }
    }
}

impl<T> Decryptor for DecryptingKey<T> where T: UnsignedModularInt + DefaultIsZeroes {}

impl<T> RandomizedDecryptor for DecryptingKey<T> where T: UnsignedModularInt + DefaultIsZeroes {}

impl<T> EncryptingKeypair for DecryptingKey<T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    type EncryptingKey = EncryptingKey<T>;
    fn encrypting_key(&self) -> EncryptingKey<T> {
        todo!()
    }
}

impl<T> ZeroizeOnDrop for DecryptingKey<T> where T: UnsignedModularInt + DefaultIsZeroes {}

#[cfg(test)]
mod tests {}
