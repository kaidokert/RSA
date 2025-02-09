use super::{oid, pkcs1v15_generate_prefix, sign, Signature, VerifyingKey};
use crate::{dummy_rng::DummyRng, Result, RsaPrivateKey};
use core::marker::PhantomData;
use digest::Digest;
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use {
    serdect::serde::{de, ser, Deserialize, Serialize},
};

use signature::{
    hazmat::PrehashSigner, DigestSigner, Keypair, RandomizedDigestSigner, RandomizedSigner, Signer,
};
use zeroize::ZeroizeOnDrop;

// New imports
use const_oid::AssociatedOid;
use crate::{Prefix, traits::UnsignedModularInt};

/// Signing key for `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug, Clone)]
pub struct SigningKey<D, T>
where
    T: UnsignedModularInt,
{
    inner: RsaPrivateKey<T>,
    prefix: Prefix,
    phantom: PhantomData<D>,
}

impl<D, T> SigningKey<D, T>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt,
{
    /// Create a new signing key with a prefix for the digest `D`.
    pub fn new(key: RsaPrivateKey<T>) -> Self {
        Self {
            inner: key,
            prefix: pkcs1v15_generate_prefix::<D>(),
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
    T: UnsignedModularInt,
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
// `*Signer` trait impls
//



//
// Other trait impls
//

impl<D, T> AsRef<RsaPrivateKey<T>> for SigningKey<D, T>
where
    T: UnsignedModularInt,
{
    fn as_ref(&self) -> &RsaPrivateKey<T> {
        &self.inner
    }
}

impl<D, T> From<RsaPrivateKey<T>> for SigningKey<D, T>
where
    T: UnsignedModularInt,
{
    fn from(key: RsaPrivateKey<T>) -> Self {
        Self::new_unprefixed(key)
    }
}

impl<D, T> From<SigningKey<D, T>> for RsaPrivateKey<T>
where
    T: UnsignedModularInt,
{
    fn from(key: SigningKey<D, T>) -> Self {
        key.inner
    }
}

impl<D, T> Keypair for SigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    type VerifyingKey = VerifyingKey<D, T>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey {
            inner: self.inner.to_public_key(),
            prefix: self.prefix.clone(),
            phantom: Default::default(),
        }
    }
}

impl<D, T> ZeroizeOnDrop for SigningKey<D, T> where T: UnsignedModularInt {}

impl<D, T> PartialEq for SigningKey<D, T>
where
    T: UnsignedModularInt,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.prefix == other.prefix
    }
}

#[cfg(feature = "serde")]
impl<D, T> Serialize for SigningKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        todo!()
    }
}

#[cfg(feature = "serde")]
impl<'de, D, T> Deserialize<'de> for SigningKey<D, T>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt,
{
    fn deserialize<De>(deserializer: De) -> core::result::Result<Self, De::Error>
    where
        De: serdect::serde::Deserializer<'de>,
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
        let priv_key = crate::RsaPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let signing_key = SigningKey::<Sha256>::new(priv_key);

        let tokens = [
            Token::Str("3054020100300d06092a864886f70d01010105000440303e020100020900cc6c6130e35b46bf0203010001020863de1ac858580019020500f65cff5d020500d46b68cb02046d9a09f102047b4e3a4f020500f45065cc")
        ];

        assert_tokens(&signing_key.readable(), &tokens);
    }
}
