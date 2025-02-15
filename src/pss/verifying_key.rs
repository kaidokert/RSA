use super::{verify_digest, Signature};
use crate::RsaPublicKey;
use const_oid::AssociatedOid;
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use signature::{hazmat::PrehashVerifier, DigestVerifier, Verifier};
#[cfg(feature = "serde")]
use {
    serdect::serde::{de, ser, Deserialize, Serialize},
};

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
    pub fn new(key: RsaPublicKey<T>) -> Self {
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
        Self::new(key)
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

#[cfg(feature = "serde")]
impl<D, T> Serialize for VerifyingKey<D, T>
where
    D: Digest,
    T: UnsignedModularInt,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!()
    }
}

#[cfg(feature = "serde")]
impl<'de, D, T> Deserialize<'de> for VerifyingKey<D, T>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt,
{
    fn deserialize<De>(deserializer: De) -> Result<Self, De::Error>
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
        /* TODO:
        let priv_key = crate::RsaPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let pub_key = priv_key.to_public_key();
        let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

        let tokens = [Token::Str(
            "3024300d06092a864886f70d01010105000313003010020900cc6c6130e35b46bf0203010001",
        )];

        assert_tokens(&verifying_key.readable(), &tokens);
        */
    }
}
