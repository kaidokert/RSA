use zeroize::DefaultIsZeroes;

use super::encrypt;
use crate::{
    traits::{RandomizedEncryptor, UnsignedModularInt},
    Result, RsaPublicKey,
};

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.2].
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptingKey<T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    pub(super) inner: RsaPublicKey<T>,
}

impl<T> EncryptingKey<T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey<T>) -> Self {
        Self { inner: key }
    }
}

impl<T> RandomizedEncryptor for EncryptingKey<T> where T: UnsignedModularInt + DefaultIsZeroes {}

#[cfg(test)]
mod tests {}
