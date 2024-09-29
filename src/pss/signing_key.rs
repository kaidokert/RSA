use super::{get_pss_signature_algo_id, sign_digest, Signature, VerifyingKey};
use crate::{Result, RsaPrivateKey};
use const_oid::AssociatedOid;
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use rand_core::CryptoRngCore;
use signature::{
    hazmat::RandomizedPrehashSigner, Keypair, RandomizedDigestSigner, RandomizedSigner,
};
use zeroize::ZeroizeOnDrop;

use crate::traits::UnsignedModularInt;

/// Signing key for producing RSASSA-PSS signatures as described in
/// [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Debug, Clone)]
pub struct SigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    inner: RsaPrivateKey<T>,
    salt_len: usize,
    phantom: PhantomData<D>,
}

impl<D, T> SigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    /// Create a new RSASSA-PSS signing key.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPrivateKey<T>) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS signing key with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey<T>, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: Default::default(),
        }
    }

    /// Generate a new random RSASSA-PSS signing key.
    /// Digest output size is used as a salt length.
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::random_with_salt_len(rng, bit_size, <D as Digest>::output_size())
    }

    /// Generate a new random RSASSA-PSS signing key with a salt of the given length.
    pub fn random_with_salt_len<R: CryptoRngCore + ?Sized>(
        rng: &mut R,
        bit_size: usize,
        salt_len: usize,
    ) -> Result<Self> {
        todo!()
    }

    /// Return specified salt length for this key
    pub fn salt_len(&self) -> usize {
        self.salt_len
    }
}

//
// `*Signer` trait impls
//

impl<D, T> ZeroizeOnDrop for SigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
}

impl<D, T> PartialEq for SigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.salt_len == other.salt_len
    }
}

#[cfg(test)]
mod tests {}
