//! Heapless RSASSA-PSS signing key. Generic over `D` (digest),
//! `T` (integer), and `M` (Montgomery parameters), mirrors
//! [`super::GenericVerifyingKey`] on the verify side and the
//! [`crate::pkcs1v15::GenericSigningKey`] shape for the sign side.
//!
//! PSS sign needs an RNG for the salt (unlike PKCS#1 v1.5 sign which
//! is deterministic) — `try_sign_with_rng_into` mirrors the
//! `RandomizedEncryptor::encrypt_with_rng_into` shape on the encrypt
//! side: caller passes `&mut R: TryCryptoRng + ?Sized`.

use crate::{
    algorithms::pss::{sign_into, sign_with_rng_into},
    errors::{Error, Result},
    key::GenericRsaPrivateKey,
    traits::{
        modular::{ModulusParams, Pow, PowBoundedExp},
        PublicKeyParts, UnsignedModularInt,
    },
};
use core::fmt;
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use rand_core::TryCryptoRng;
use zeroize::Zeroize;

/// Signing key for RSASSA-PSS — heapless variant.
///
/// Generic over the digest `D`, integer type `T`, and Montgomery parameters
/// `M`. Holds a [`GenericRsaPrivateKey<T, M>`] plus the salt length to use
/// when signing (caller-chosen at construction; defaults to
/// `<D as Digest>::output_size()` via [`new`](Self::new)).
///
/// PSS has no DigestInfo prefix — `D` is purely a phantom marker for the
/// digest algorithm used by both encode and verify.
pub struct GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize,
    M: ModulusParams<Modulus = T>,
{
    pub(super) inner: GenericRsaPrivateKey<T, M>,
    pub(super) salt_len: usize,
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
            .field("salt_len", &self.salt_len)
            .finish()
    }
}

// Manual Clone impls — split by `alloc` cfg to avoid imposing
// the `M::MontgomeryForm: Clone` bound on heapless backends where it
// isn't needed (only `GenericRsaPrivateKey`'s `precomputed` field
// requires it, and that field is `cfg(alloc)`).
#[cfg(feature = "alloc")]
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
            salt_len: self.salt_len,
            phantom: PhantomData,
        }
    }
}

#[cfg(not(feature = "alloc"))]
impl<D, T, M> Clone for GenericSigningKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + Zeroize + Clone,
    M: ModulusParams<Modulus = T> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            salt_len: self.salt_len,
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
    /// Construct with salt length = `D::output_size()` (standard choice
    /// per RFC 8017 § 8.1).
    pub fn new(key: GenericRsaPrivateKey<T, M>) -> Self {
        Self {
            inner: key,
            salt_len: <D as Digest>::output_size(),
            phantom: PhantomData,
        }
    }

    /// Construct with a custom salt length.
    pub fn new_with_salt_len(key: GenericRsaPrivateKey<T, M>, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: PhantomData,
        }
    }

    /// Salt length this key will use when signing.
    pub fn salt_len(&self) -> usize {
        self.salt_len
    }
}

// Borrow the inner private-key components — `AsRef` impl mirrors
// the verifier's `AsRef<GenericRsaPublicKey<T, M>>`.
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

// RNG-taking sign methods use base blinding in addition to the salt
// sampling. The extra bounds are satisfied by both backends we
// support.
impl<D, T, M> GenericSigningKey<D, T, M>
where
    D: Digest + FixedOutputReset,
    T: UnsignedModularInt + Zeroize + crate::traits::modular::TryRandomMod,
    T::Bytes: Zeroize,
    M: ModulusParams<Modulus = T> + crate::traits::modular::CtModulusParams,
    M::MontgomeryForm: Pow<M>
        + PowBoundedExp<M>
        + crate::traits::modular::InvertCt<M>
        + crate::traits::modular::MulCt<M>,
{
    /// Sign `msg` (hashed internally with `D`) into `sig_storage`, drawing
    /// the PSS salt AND the RSA base-blinding factor from `rng`. Uses
    /// `em_storage` and `salt_storage` as scratch. All three buffers
    /// must be at least the relevant sizes (`em_storage`:
    /// `em_bits.div_ceil(8)`; `sig_storage`: `n.size()`;
    /// `salt_storage`: `self.salt_len()`).
    ///
    /// Mirrors [`crate::traits::RandomizedEncryptor::encrypt_with_rng_into`]:
    /// caller owns storage, returned slice borrows from `sig_storage`.
    pub fn try_sign_with_rng_into<'sig, R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
        em_storage: &mut [u8],
        sig_storage: &'sig mut [u8],
        salt_storage: &mut [u8],
    ) -> Result<&'sig [u8]> {
        let digest = D::digest(msg);
        self.try_sign_prehash_with_rng_into(
            rng,
            digest.as_ref(),
            em_storage,
            sig_storage,
            salt_storage,
        )
    }

    /// Sign a precomputed `prehash` (`D::output_size()` bytes) into
    /// `sig_storage`, drawing the PSS salt AND the RSA base-blinding
    /// factor from `rng`.
    ///
    /// Returns [`Error::InputNotHashed`] if `prehash.len()` doesn't match
    /// `D::output_size()`. Returns [`Error::OutputBufferTooSmall`] if
    /// `salt_storage.len() < self.salt_len()`.
    pub fn try_sign_prehash_with_rng_into<'sig, R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
        em_storage: &mut [u8],
        sig_storage: &'sig mut [u8],
        salt_storage: &mut [u8],
    ) -> Result<&'sig [u8]> {
        if prehash.len() != <D as Digest>::output_size() {
            return Err(Error::InputNotHashed);
        }
        let salt = salt_storage
            .get_mut(..self.salt_len)
            .ok_or(Error::OutputBufferTooSmall)?;
        rng.try_fill_bytes(salt).map_err(|_| Error::Rng)?;
        let mut hash = D::new();
        sign_with_rng_into(
            rng,
            self.inner.n_params(),
            crate::traits::keys::PrivateKeyParts::d(&self.inner),
            self.inner.e(),
            prehash,
            salt,
            self.inner.size(),
            &mut hash,
            em_storage,
            sig_storage,
        )
    }
}

// Deterministic (caller-supplied salt, no RNG) variant kept in a
// separate impl block so it doesn't require the blinding bounds —
// callers who explicitly want a deterministic sign path (typically
// tests) don't need the extra trait impls on `T` / `M`.
impl<D, T, M> GenericSigningKey<D, T, M>
where
    D: Digest + FixedOutputReset,
    T: UnsignedModularInt + Zeroize,
    T::Bytes: Zeroize,
    M: ModulusParams<Modulus = T> + crate::traits::modular::CtModulusParams,
    M::MontgomeryForm: Pow<M> + PowBoundedExp<M>,
{
    /// Sign with caller-supplied salt — useful for determinism in tests.
    ///
    /// Returns [`Error::InputNotHashed`] if `prehash.len()` doesn't match
    /// `D::output_size()`. Returns [`Error::InvalidArguments`] if
    /// `salt.len() != self.salt_len()` — a mismatch silently produces a
    /// signature that no verifier configured with the key's advertised
    /// `salt_len` will accept, so we reject it up front.
    pub fn try_sign_prehash_with_salt_into<'sig>(
        &self,
        prehash: &[u8],
        salt: &[u8],
        em_storage: &mut [u8],
        sig_storage: &'sig mut [u8],
    ) -> Result<&'sig [u8]> {
        if prehash.len() != <D as Digest>::output_size() {
            return Err(Error::InputNotHashed);
        }
        if salt.len() != self.salt_len {
            return Err(Error::InvalidArguments);
        }
        let mut hash = D::new();
        sign_into(
            self.inner.n_params(),
            crate::traits::keys::PrivateKeyParts::d(&self.inner),
            self.inner.e(),
            prehash,
            salt,
            self.inner.size(),
            &mut hash,
            em_storage,
            sig_storage,
        )
    }
}

// Allow callers to wrap a `GenericSigningKey` in `zeroize::Zeroizing<_>`
// or invoke `.zeroize()` directly. The salt_len is public; only the
// inner `GenericRsaPrivateKey` carries secret bytes.
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

#[cfg(test)]
mod tests {
    // End-to-end round-trip test for `try_sign_with_rng_into` on the boxed alias
    // (`pss::SigningKey<D>`). Exercises the full stack: wrapper (which
    // internally samples salt AND blinding `r`) →
    // `algorithms::pss::sign_with_rng_into` →
    // `rsa_private_op_and_check_blinded` → `TryRandomMod` →
    // `rsa_private_op_blinded` (InvertCt/MulCt). The heapless
    // exact-width equivalent lives in `modmath_support.rs`
    // (`pss_signing_key_try_sign_prehash_with_rng_into_round_trip_2048_sha1`).
    #[test]
    #[cfg(feature = "encoding")]
    fn signing_key_try_sign_with_rng_into_round_trip() {
        use crate::pss::{Signature, SigningKey, VerifyingKey};
        use crate::RsaPrivateKey;
        use pkcs1::DecodeRsaPrivateKey;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use sha2::Sha256;
        use signature::Verifier;

        const PRIV_KEY_PKCS1_PEM: &str =
            include_str!("../../tests/examples/pkcs1/rsa2048-priv.pem");

        let priv_key = RsaPrivateKey::from_pkcs1_pem(PRIV_KEY_PKCS1_PEM).unwrap();
        let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
        let verifying_key = VerifyingKey::<Sha256>::new(priv_key.to_public_key());

        let msg: &[u8] = b"blinded pss sign test message";
        let mut rng = ChaCha8Rng::from_seed([42; 32]);

        // 2048-bit key → 256-byte signature and EM;
        // salt_len defaults to `Sha256::output_size()` = 32.
        let mut em_storage = [0u8; 256];
        let mut sig_storage = [0u8; 256];
        let mut salt_storage = [0u8; 32];
        let sig_slice = signing_key
            .try_sign_with_rng_into(
                &mut rng,
                msg,
                &mut em_storage,
                &mut sig_storage,
                &mut salt_storage,
            )
            .unwrap();
        assert_eq!(sig_slice.len(), 256);

        let sig = Signature::try_from(sig_slice).unwrap();
        verifying_key.verify(msg, &sig).unwrap();
    }
}
