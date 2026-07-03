//! Heapless `RSASSA-PKCS1-v1_5` signing key. Generic over `D` (digest),
//! `T` (integer), and `M` (Montgomery parameters), mirrors the shape of
//! [`super::GenericVerifyingKey`] on the verify side.
//!
//! Compatible with the no_alloc / `wip-private-key` build path —
//! [`GenericRsaPrivateKey<T, M>`] storage, fixed-size [`Prefix`] for
//! the DigestInfo prefix, caller-supplied scratch buffers for the EM
//! and signature output.

#[cfg(feature = "alloc")]
use super::pkcs1v15_generate_prefix;
#[cfg(not(feature = "alloc"))]
use super::{pkcs1v15_generate_prefix_helper, Prefix};
use super::{sign_into, GenericVerifyingKey};
use crate::{
    errors::Result,
    key::GenericRsaPrivateKey,
    traits::{
        modular::{ModulusParams, Pow, PowBoundedExp},
        PublicKeyParts, UnsignedModularInt,
    },
};
use const_oid::AssociatedOid;
use core::fmt;
use core::marker::PhantomData;
use digest::Digest;
use zeroize::Zeroize;

/// Signing key for `RSASSA-PKCS1-v1_5` signatures — heapless variant.
///
/// Generic over the digest `D`, integer type `T`, and Montgomery parameters
/// `M`. Holds a [`GenericRsaPrivateKey<T, M>`] plus the precomputed
/// DigestInfo prefix for `D`.
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

// Manual `Debug` — `#[derive]` would synthesize unwanted bounds on
// `D`/`T`/`M`; the inner private key already redacts `d`.
impl<D, T, M> fmt::Debug for GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
    GenericRsaPrivateKey<T, M>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericSigningKey")
            .field("inner", &self.inner)
            .field("prefix", &self.prefix)
            .finish()
    }
}

// Manual Clone impls — split by `private-key` cfg to avoid imposing
// the `M::MontgomeryForm: Clone` bound on heapless backends where it
// isn't needed (only `GenericRsaPrivateKey`'s `precomputed` field
// requires it, and that field is `cfg(private-key)`).
#[cfg(feature = "private-key")]
impl<D, T, M> Clone for GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize + Clone,
    M: ModulusParams<Modulus = T> + Clone,
    M::MontgomeryForm: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            prefix: self.prefix.clone(),
            phantom: PhantomData,
        }
    }
}

#[cfg(not(feature = "private-key"))]
impl<D, T, M> Clone for GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize + Clone,
    M: ModulusParams<Modulus = T> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            prefix: self.prefix.clone(),
            phantom: PhantomData,
        }
    }
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
    T::Bytes: Zeroize,
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
            crate::traits::keys::PrivateKeyParts::d(&self.inner),
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
    ///
    /// Returns [`Error::InputNotHashed`] if `prehash.len()` doesn't match
    /// `D::output_size()` — a mismatch would silently produce malformed
    /// PKCS#1 v1.5 padding rather than a usable signature.
    pub fn try_sign_prehash_into<'sig>(
        &self,
        prehash: &[u8],
        em_storage: &mut [u8],
        sig_storage: &'sig mut [u8],
    ) -> Result<&'sig [u8]> {
        if prehash.len() != <D as Digest>::output_size() {
            return Err(crate::errors::Error::InputNotHashed);
        }
        let k = self.inner.size();
        sign_into(
            self.inner.n_params(),
            crate::traits::keys::PrivateKeyParts::d(&self.inner),
            self.inner.e(),
            self.prefix.as_ref(),
            prehash,
            k,
            em_storage,
            sig_storage,
        )
    }
}

// Allow callers to wrap a `GenericSigningKey` in `zeroize::Zeroizing<_>`
// or invoke `.zeroize()` directly. The prefix is public DigestInfo
// material; only the inner `GenericRsaPrivateKey` carries secret bytes.
// Same pattern as the canonical Zeroize impls on `GenericRsaPrivateKey`
// (PR #24) and `ModMathForm` (PR #17).
impl<D, T, M> Zeroize for GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
{
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<D, T, M> GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
{
    /// Derive the matching [`GenericVerifyingKey`] from this signing
    /// key, preserving the existing DigestInfo prefix (so unprefixed
    /// signing keys yield unprefixed verifying keys). Not named
    /// `verifying_key` because that would shadow
    /// [`signature::Keypair::verifying_key`] for callers using
    /// method-call syntax.
    pub fn to_verifying_key(&self) -> GenericVerifyingKey<D, T, M>
    where
        crate::key::GenericRsaPublicKey<T, M>: Clone,
    {
        GenericVerifyingKey {
            inner: self.inner.as_public().clone(),
            prefix: self.prefix.clone(),
            phantom: PhantomData,
        }
    }
}
