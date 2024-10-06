use super::{oid, pkcs1v15_generate_prefix, verify, Signature};
use crate::traits::PublicKeyParts;
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
pub struct VerifyingKey<D, T>
where
    T: UnsignedModularInt,
{
    pub(super) inner: RsaPublicKey<T>,
    pub(super) prefix: Prefix,
    pub(super) phantom: PhantomData<D>,
}

impl<D, T> VerifyingKey<D, T>
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

impl<D, T> VerifyingKey<D, T>
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

impl<D, T> DigestVerifier<D, Signature<T>> for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn verify_digest(&self, digest: D, signature: &Signature<T>) -> signature::Result<()> {
        let mut cloned_t = (*self.inner.n()).to_be_bytes();
        verify(
            &self.inner,
            &self.prefix,
            &digest.finalize(),
            &signature.inner,
            signature.len,
            cloned_t.as_mut(),
        )
        .map_err(|e| e.into())
    }
}

impl<D, T> PrehashVerifier<Signature<T>> for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature<T>) -> signature::Result<()> {
        let mut cloned_t = (*self.inner.n()).to_be_bytes();
        verify(
            &self.inner,
            &self.prefix,
            prehash,
            &signature.inner,
            signature.len,
            cloned_t.as_mut(),
        )
        .map_err(|e| e.into())
    }
}

impl<D, T> Verifier<Signature<T>> for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt + core::fmt::Debug,
{
    fn verify(&self, msg: &[u8], signature: &Signature<T>) -> Result<(), signature::Error> {
        let mut cloned_t = (*self.inner.n()).to_be_bytes();
        verify(
            &self.inner,
            &self.prefix.clone(),
            &D::digest(msg),
            &signature.inner,
            signature.len,
            cloned_t.as_mut(),
        )
        .map_err(|e| e.into())
    }
}

//
// Other trait impls
//

impl<D, T> AsRef<RsaPublicKey<T>> for VerifyingKey<D, T>
where
    T: UnsignedModularInt,
{
    fn as_ref(&self) -> &RsaPublicKey<T> {
        &self.inner
    }
}

// Implemented manually so we don't have to bind D with Clone
impl<D, T> Clone for VerifyingKey<D, T>
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

impl<D, T> From<RsaPublicKey<T>> for VerifyingKey<D, T>
where
    T: UnsignedModularInt,
{
    fn from(key: RsaPublicKey<T>) -> Self {
        Self::new_unprefixed(key)
    }
}

impl<D, T> From<VerifyingKey<D, T>> for RsaPublicKey<T>
where
    T: UnsignedModularInt,
{
    fn from(key: VerifyingKey<D, T>) -> Self {
        key.inner
    }
}

impl<D, T> PartialEq for VerifyingKey<D, T>
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
