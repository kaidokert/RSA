//! Heapless `RSASSA-PKCS1-v1_5` signing key. Generic over `D` (digest),
//! `T` (integer), and `M` (Montgomery parameters), mirrors the shape of
//! [`super::GenericVerifyingKey`] on the verify side.
//!
//! Compatible with the no_alloc / `wip-private-key` build path —
//! [`GenericRsaPrivateKey<T, M>`] storage, fixed-size [`Prefix`] for
//! the DigestInfo prefix, caller-supplied scratch buffers for the EM
//! and signature output.

use super::sign_into;
#[cfg(feature = "alloc")]
use super::{pkcs1v15_generate_prefix, GenericVerifyingKey};
#[cfg(not(feature = "alloc"))]
use super::{pkcs1v15_generate_prefix_helper, Prefix};
use crate::{
    errors::Result,
    key::GenericRsaPrivateKey,
    traits::{
        modular::{ModulusParams, Pow, PowBoundedExp},
        PublicKeyParts, UnsignedModularInt,
    },
};
use const_oid::AssociatedOid;
use core::marker::PhantomData;
use digest::Digest;
use zeroize::Zeroize;

/// Signing key for `RSASSA-PKCS1-v1_5` signatures — heapless variant.
///
/// Generic over the digest `D`, integer type `T`, and Montgomery parameters
/// `M`. Holds a [`GenericRsaPrivateKey<T, M>`] plus the precomputed
/// DigestInfo prefix for `D`.
#[derive(Clone)]
pub struct GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
{
    pub(super) inner: GenericRsaPrivateKey<T, M>,
    #[cfg(feature = "alloc")]
    pub(super) prefix: alloc::vec::Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub(super) prefix: Prefix,
    pub(super) phantom: PhantomData<D>,
}

impl<D, T, M> GenericSigningKey<D, T, M>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
{
    /// Create a new signing key with a precomputed prefix for digest `D`.
    pub fn new(key: GenericRsaPrivateKey<T, M>) -> Self {
        Self {
            inner: key,
            #[cfg(feature = "alloc")]
            prefix: pkcs1v15_generate_prefix::<D>(),
            #[cfg(not(feature = "alloc"))]
            prefix: pkcs1v15_generate_prefix_helper::<D>(),
            phantom: PhantomData,
        }
    }
}

impl<D, T, M> GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
{
    /// Create a new signing key with an empty prefix (raw signatures, no
    /// DigestInfo wrapper). Unusual — most callers want [`new`] instead.
    pub fn new_unprefixed(key: GenericRsaPrivateKey<T, M>) -> Self {
        Self {
            inner: key,
            #[cfg(feature = "alloc")]
            prefix: alloc::vec::Vec::new(),
            #[cfg(not(feature = "alloc"))]
            prefix: Prefix::new(),
            phantom: PhantomData,
        }
    }
}

// Borrow the inner private-key components — `AsRef` impl mirrors
// the verifier's `AsRef<GenericRsaPublicKey<T, M>>` (`verifying_key.rs:172`).
impl<D, T, M> AsRef<GenericRsaPrivateKey<T, M>> for GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
{
    fn as_ref(&self) -> &GenericRsaPrivateKey<T, M> {
        &self.inner
    }
}

impl<D, T, M> GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
    M::MontgomeryForm: Pow<M> + PowBoundedExp<M>,
{
    /// Sign `msg` (hashed internally with `D`) into `sig_storage`.
    /// Uses `em_storage` as scratch for the EM encoding.
    ///
    /// Both buffers must be at least `self.inner.size()` bytes.
    /// Mirrors the shape of
    /// [`crate::traits::RandomizedEncryptor::encrypt_with_rng_into`] on
    /// the encrypt side: caller owns storage, returned slice borrows from
    /// `sig_storage` with the same lifetime.
    pub fn try_sign_into<'sig>(
        &self,
        msg: &[u8],
        em_storage: &mut [u8],
        sig_storage: &'sig mut [u8],
    ) -> Result<&'sig [u8]> {
        let digest = D::digest(msg);
        let k = self.inner.size();
        sign_into(
            self.inner.n_params(),
            crate::traits::keys::GenericPrivateKeyParts::d(&self.inner),
            self.inner.e(),
            self.prefix.as_ref(),
            digest.as_ref(),
            k,
            em_storage,
            sig_storage,
        )
    }

    /// Sign a precomputed `prehash` (`D::output_size()` bytes) into
    /// `sig_storage`. The caller is responsible for the hash; this skips
    /// the internal `D::digest(msg)` step.
    pub fn try_sign_prehash_into<'sig>(
        &self,
        prehash: &[u8],
        em_storage: &mut [u8],
        sig_storage: &'sig mut [u8],
    ) -> Result<&'sig [u8]> {
        let k = self.inner.size();
        sign_into(
            self.inner.n_params(),
            crate::traits::keys::GenericPrivateKeyParts::d(&self.inner),
            self.inner.e(),
            self.prefix.as_ref(),
            prehash,
            k,
            em_storage,
            sig_storage,
        )
    }
}

#[cfg(feature = "alloc")]
impl<D, T, M> GenericSigningKey<D, T, M>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
{
    /// Derive the matching [`GenericVerifyingKey`] from this signing key.
    pub fn verifying_key(&self) -> GenericVerifyingKey<D, T, M>
    where
        GenericRsaPrivateKey<T, M>: Clone,
        crate::key::GenericRsaPublicKey<T, M>: Clone,
    {
        GenericVerifyingKey::new(self.inner.as_public().clone())
    }
}
