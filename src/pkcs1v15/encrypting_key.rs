use super::encrypt;
use crate::{
    traits::{RandomizedEncryptor, UnsignedModularInt},
    Result, RsaPublicKey,
};
use rand_core::CryptoRngCore;

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.2].
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptingKey<T>
where
    T: UnsignedModularInt,
{
    pub(super) inner: RsaPublicKey<T>,
}

impl<T> EncryptingKey<T>
where
    T: UnsignedModularInt,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey<T>) -> Self {
        Self { inner: key }
    }
}

impl<T> RandomizedEncryptor for EncryptingKey<T>
where
    T: UnsignedModularInt,
    <T as num_traits::FromBytes>::Bytes: num_traits::ops::bytes::NumBytes + Default,
{
    fn encrypt_with_rng<'a, R: CryptoRngCore + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        encrypt(rng, &self.inner, msg, storage)
    }
}

#[cfg(test)]
mod tests {}
