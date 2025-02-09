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
#[cfg(feature = "serde")]
use {
    serdect::serde::{de, ser, Deserialize, Serialize},
};

use crate::traits::UnsignedModularInt;

/// Signing key for producing "blinded" RSASSA-PSS signatures as described in
/// [draft-irtf-cfrg-rsa-blind-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/).
#[derive(Debug, Clone)]
pub struct BlindedSigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    inner: RsaPrivateKey<T>,
    salt_len: usize,
    phantom: PhantomData<D>,
}

impl<D, T> BlindedSigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPrivateKey<T>) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey<T>, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: Default::default(),
        }
    }

    /// Create a new random RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    /// Digest output size is used as a salt length.
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::random_with_salt_len(rng, bit_size, <D as Digest>::output_size())
    }

    /// Create a new random RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
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

//
// Other trait impls
//

impl<D, T> AsRef<RsaPrivateKey<T>> for BlindedSigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn as_ref(&self) -> &RsaPrivateKey<T> {
        &self.inner
    }
}

impl<D, T> From<RsaPrivateKey<T>> for BlindedSigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn from(key: RsaPrivateKey<T>) -> Self {
        Self::new(key)
    }
}

impl<D, T> From<BlindedSigningKey<D, T>> for RsaPrivateKey<T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn from(key: BlindedSigningKey<D, T>) -> Self {
        key.inner
    }
}

impl<D, T> Keypair for BlindedSigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    type VerifyingKey = VerifyingKey<D, T>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey {
            inner: self.inner.to_public_key(),
            salt_len: self.salt_len,
            phantom: Default::default(),
        }
    }
}

impl<D, T> ZeroizeOnDrop for BlindedSigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
}

impl<D, T> PartialEq for BlindedSigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.salt_len == other.salt_len
    }
}

#[cfg(feature = "serde")]
impl<D, T> Serialize for BlindedSigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!()
    }
}

#[cfg(feature = "serde")]
impl<'de, D, T> Deserialize<'de> for BlindedSigningKey<D, T>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt,
{
    fn deserialize<De>(deserializer: De) -> core::result::Result<Self, De::Error>
    where
        De: serde::Deserializer<'de>,
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
        use serde_test::{assert_tokens, Configure, Token};
        use sha2::Sha256;

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = BlindedSigningKey::<Sha256>::new(
            RsaPrivateKey::new(&mut rng, 64).expect("failed to generate key"),
        );

        let tokens = [
            Token::Str("3054020100300d06092a864886f70d01010105000440303e020100020900cc6c6130e35b46bf0203010001020863de1ac858580019020500f65cff5d020500d46b68cb02046d9a09f102047b4e3a4f020500f45065cc")
        ];
        assert_tokens(&signing_key.readable(), &tokens);
    }
}
