use super::{verify, Signature};
use crate::{traits::UnsignedModularInt, RsaPublicKey};
use core::marker::PhantomData;
use digest::Digest;

use zeroize::DefaultIsZeroes;

use signature::Verifier;

/// Verifying key for `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug)]
pub struct VerifyingKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    pub(super) inner: RsaPublicKey<T>,
    pub(super) prefix: PhantomData<D>,
    pub(super) phantom: PhantomData<D>,
}

impl<D, T> VerifyingKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    /// Create a new verifying key with a prefix for the digest `D`.
    pub fn new(key: RsaPublicKey<T>) -> Self {
        Self {
            inner: key,
            prefix: Default::default(),
            phantom: Default::default(),
        }
    }
}

impl<D, T> VerifyingKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    /// Create a new verifying key from an RSA public key with an empty prefix.
    ///
    /// ## Note: unprefixed signatures are uncommon
    ///
    /// In most cases you'll want to use [`VerifyingKey::new`] instead.
    pub fn new_unprefixed(key: RsaPublicKey<T>) -> Self {
        Self {
            inner: key,
            prefix: Default::default(),
            phantom: Default::default(),
        }
    }
}

//
// `*Verifier` trait impls
//
impl<D, T> Verifier<Signature<T>> for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn verify(&self, msg: &[u8], signature: &Signature<T>) -> Result<(), signature::Error> {
        verify(
            &self.inner,
            &[0x0A_u8; 1],
            &D::digest(msg),
            &signature.inner,
            signature.len,
        )
        .map_err(|e| e.into())
    }
}

//
// Other trait impls
//

impl<D, T> AsRef<RsaPublicKey<T>> for VerifyingKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn as_ref(&self) -> &RsaPublicKey<T> {
        &self.inner
    }
}

// Implemented manually so we don't have to bind D with Clone
impl<D, T> Clone for VerifyingKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            prefix: self.prefix.clone(),
            phantom: Default::default(),
        }
    }
}

impl<D, T> From<RsaPublicKey<T>> for VerifyingKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn from(key: RsaPublicKey<T>) -> Self {
        Self::new_unprefixed(key)
    }
}

impl<D, T> From<VerifyingKey<D, T>> for RsaPublicKey<T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn from(key: VerifyingKey<D, T>) -> Self {
        key.inner
    }
}

impl<D, T> PartialEq for VerifyingKey<D, T>
where
    T: UnsignedModularInt + DefaultIsZeroes,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.prefix == other.prefix
    }
}

#[cfg(test)]
mod tests {}
