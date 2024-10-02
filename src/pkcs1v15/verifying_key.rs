use super::{oid, pkcs1v15_generate_prefix, verify, Signature};
use crate::RsaPublicKey;
use crate::{traits::UnsignedModularInt, Prefix};
use const_oid::AssociatedOid;
use core::marker::PhantomData;
use digest::Digest;

use signature::{hazmat::PrehashVerifier, DigestVerifier, Verifier};

/// Verifying key for `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug)]
pub struct VerifyingKey<D, T, const N: usize>
where
    T: UnsignedModularInt,
{
    pub(super) inner: RsaPublicKey<T>,
    pub(super) prefix: Prefix,
    pub(super) phantom: PhantomData<D>,
}

impl<D, T, const N: usize> VerifyingKey<D, T, N>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt,
{
    /// Create a new verifying key with a prefix for the digest `D`.
    pub fn new(key: RsaPublicKey<T>) -> Self {
        Self {
            inner: key,
            prefix: pkcs1v15_generate_prefix::<D>(),
            phantom: Default::default(),
        }
    }
}

impl<D, T, const N: usize> VerifyingKey<D, T, N>
where
    T: UnsignedModularInt,
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

impl<D, T, const N: usize> DigestVerifier<D, Signature<T>> for VerifyingKey<D, T, N>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn verify_digest(&self, digest: D, signature: &Signature<T>) -> signature::Result<()> {
        let mut storage = [0u8; N];
        verify(
            &self.inner,
            &self.prefix,
            &digest.finalize(),
            &signature.inner,
            signature.len,
            &mut storage,
        )
        .map_err(|e| e.into())
    }
}

impl<D, T, const N: usize> PrehashVerifier<Signature<T>> for VerifyingKey<D, T, N>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature<T>) -> signature::Result<()> {
        let mut storage = [0u8; N];
        verify(
            &self.inner,
            &self.prefix,
            prehash,
            &signature.inner,
            signature.len,
            &mut storage,
        )
        .map_err(|e| e.into())
    }
}

impl<D, T, const N: usize> Verifier<Signature<T>> for VerifyingKey<D, T, N>
where
    D: Digest,
    T: UnsignedModularInt + core::fmt::Debug,
{
    fn verify(&self, msg: &[u8], signature: &Signature<T>) -> Result<(), signature::Error> {
        let mut storage = [0u8; N];
        verify(
            &self.inner,
            &self.prefix.clone(),
            &D::digest(msg),
            &signature.inner,
            signature.len,
            &mut storage,
        )
        .map_err(|e| e.into())
    }
}

//
// Other trait impls
//

impl<D, T, const N: usize> AsRef<RsaPublicKey<T>> for VerifyingKey<D, T, N>
where
    T: UnsignedModularInt,
{
    fn as_ref(&self) -> &RsaPublicKey<T> {
        &self.inner
    }
}

// Implemented manually so we don't have to bind D with Clone
impl<D, T, const N: usize> Clone for VerifyingKey<D, T, N>
where
    T: UnsignedModularInt,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            prefix: self.prefix.clone(),
            phantom: Default::default(),
        }
    }
}

impl<D, T, const N: usize> From<RsaPublicKey<T>> for VerifyingKey<D, T, N>
where
    T: UnsignedModularInt,
{
    fn from(key: RsaPublicKey<T>) -> Self {
        Self::new_unprefixed(key)
    }
}

impl<D, T, const N: usize> From<VerifyingKey<D, T, N>> for RsaPublicKey<T>
where
    T: UnsignedModularInt,
{
    fn from(key: VerifyingKey<D, T, N>) -> Self {
        key.inner
    }
}

impl<D, T, const N: usize> PartialEq for VerifyingKey<D, T, N>
where
    T: UnsignedModularInt,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.prefix == other.prefix
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
        todo!()
    }
}
