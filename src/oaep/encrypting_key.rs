use super::encrypt_digest;
use crate::{
    traits::{RandomizedEncryptor, UnsignedModularInt},
    Result, RsaPublicKey,
};
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use rand_core::CryptoRngCore;

use heapless::String;

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.1].
///
/// [RFC8017 § 7.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[derive(Debug, Clone)]
pub struct EncryptingKey<T, D, MGD = D>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
    inner: RsaPublicKey<T>,
    label: Option<String<128>>, // todo: make it not fixed
    phantom: PhantomData<D>,
    mg_phantom: PhantomData<MGD>,
}

impl<T, D, MGD> EncryptingKey<T, D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey<T>) -> Self {
        Self {
            inner: key,
            label: None,
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }

    /// Create a new verifying key from an RSA public key using provided label
    pub fn new_with_label<S: AsRef<str>>(key: RsaPublicKey<T>, label: S) -> Self {
        Self {
            inner: key,
            label: None,
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }
}

impl<T, D, MGD> RandomizedEncryptor for EncryptingKey<T, D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
    fn encrypt_with_rng<'a, R: CryptoRngCore + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        encrypt_digest::<T, _, D, MGD>(rng, &self.inner, msg, self.label.as_ref().cloned(), storage)
    }
}

impl<T, D, MGD> PartialEq for EncryptingKey<T, D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.label == other.label
    }
}

#[cfg(test)]
mod tests {}
