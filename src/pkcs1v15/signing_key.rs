use super::{sign, Signature, VerifyingKey};
use crate::{key::RsaPrivateKey, traits::UnsignedModularInt, Result};
use core::marker::PhantomData;

use zeroize::DefaultIsZeroes;
use zeroize::ZeroizeOnDrop;

/// Signing key for `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug, Clone)]
pub struct SigningKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    inner: RsaPrivateKey<T>,
    prefix: PhantomData<D>,
    phantom: PhantomData<D>,
}

impl<D, T> SigningKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    /// Create a new signing key with a prefix for the digest `D`.
    pub fn new(key: RsaPrivateKey<T>) -> Self {
        Self {
            inner: key,
            prefix: Default::default(),
            phantom: Default::default(),
        }
    }

    /// Generate a new signing key with a prefix for the digest `D`.
    pub fn random(bit_size: usize) -> Result<Self> {
        todo!()
    }
}

impl<D, T> SigningKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    /// Create a new signing key from the give RSA private key with an empty prefix.
    ///
    /// ## Note: unprefixed signatures are uncommon
    ///
    /// In most cases you'll want to use [`SigningKey::new`].
    pub fn new_unprefixed(key: RsaPrivateKey<T>) -> Self {
        Self {
            inner: key,
            prefix: Default::default(),
            phantom: Default::default(),
        }
    }

    /// Generate a new signing key with an empty prefix.
    pub fn random_unprefixed(bit_size: usize) -> Result<Self> {
        todo!()
    }
}

//
// Other trait impls
//

impl<D, T> AsRef<RsaPrivateKey<T>> for SigningKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn as_ref(&self) -> &RsaPrivateKey<T> {
        &self.inner
    }
}

impl<D, T> From<RsaPrivateKey<T>> for SigningKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn from(key: RsaPrivateKey<T>) -> Self {
        Self::new_unprefixed(key)
    }
}

impl<D, T> From<SigningKey<D, T>> for RsaPrivateKey<T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn from(key: SigningKey<D, T>) -> Self {
        key.inner
    }
}

impl<D, T> ZeroizeOnDrop for SigningKey<D, T> where T: UnsignedModularInt + DefaultIsZeroes {}

impl<D, T> PartialEq for SigningKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.prefix == other.prefix
    }
}

#[cfg(test)]
mod tests {}
