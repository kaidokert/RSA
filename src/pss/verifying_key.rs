use super::{verify_digest, Signature};
use crate::RsaPublicKey;
use const_oid::AssociatedOid;
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use signature::{hazmat::PrehashVerifier, DigestVerifier, Verifier};

use crate::traits::UnsignedModularInt;

/// Verifying key for checking the validity of RSASSA-PSS signatures as
/// described in [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Debug)]
pub struct VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    pub(super) inner: RsaPublicKey<T>,
    pub(super) salt_len: usize,
    pub(super) phantom: PhantomData<D>,
}

impl<D, T> VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    /// Create a new RSASSA-PSS verifying key.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPublicKey<T>, storage: &mut [u8]) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS verifying key.
    pub fn new_with_salt_len(key: RsaPublicKey<T>, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: Default::default(),
        }
    }

    /// Return specified salt length for this key
    pub fn salt_len(&self) -> usize {
        self.salt_len
    }
}

//
// `*Verifier` trait impls
//

impl<D, T> DigestVerifier<D, Signature<T>> for VerifyingKey<D, T>
where
    D: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
    fn verify_digest(&self, digest: D, signature: &Signature<T>) -> signature::Result<()> {
        verify_digest::<D, T>(
            &self.inner,
            &digest.finalize(),
            &signature.inner,
            signature.len,
            self.salt_len,
        )
        .map_err(|e| e.into())
    }
}

impl<D, T> PrehashVerifier<Signature<T>> for VerifyingKey<D, T>
where
    D: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature<T>) -> signature::Result<()> {
        verify_digest::<D, T>(
            &self.inner,
            prehash,
            &signature.inner,
            signature.len,
            self.salt_len,
        )
        .map_err(|e| e.into())
    }
}

impl<D, T> Verifier<Signature<T>> for VerifyingKey<D, T>
where
    D: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
    fn verify(&self, msg: &[u8], signature: &Signature<T>) -> signature::Result<()> {
        verify_digest::<D, T>(
            &self.inner,
            &D::digest(msg),
            &signature.inner,
            signature.len,
            self.salt_len,
        )
        .map_err(|e| e.into())
    }
}

//
// Other trait impls
//

impl<D, T> AsRef<RsaPublicKey<T>> for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn as_ref(&self) -> &RsaPublicKey<T> {
        &self.inner
    }
}

// Implemented manually so we don't have to bind D with Clone
impl<D, T> Clone for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            salt_len: self.salt_len,
            phantom: Default::default(),
        }
    }
}

impl<D, T> From<RsaPublicKey<T>> for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn from(key: RsaPublicKey<T>) -> Self {
        let mut storage = [0u8; 1024]; // todo storage
        Self::new(key, &mut storage)
    }
}

impl<D, T> From<VerifyingKey<D, T>> for RsaPublicKey<T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn from(key: VerifyingKey<D, T>) -> Self {
        key.inner
    }
}

impl<D, T> PartialEq for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.salt_len == other.salt_len
    }
}
