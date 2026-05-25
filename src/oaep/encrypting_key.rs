use super::encrypt_digest_into;
#[cfg(not(feature = "alloc"))]
use super::Label;
use crate::traits::{modular::ModulusParams, PublicKeyParts, UnsignedModularInt};
use crate::{traits::RandomizedEncryptor, GenericRsaPublicKey, Result};
#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;
#[cfg(feature = "alloc")]
use crypto_bigint::{modular::BoxedMontyParams, BoxedUint};
use digest::{Digest, FixedOutputReset};
use rand_core::{CryptoRng, TryCryptoRng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.1].
///
/// [RFC8017 § 7.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "GenericRsaPublicKey<T, M>: Serialize",
        deserialize = "GenericRsaPublicKey<T, M>: serde::de::DeserializeOwned"
    ))
)]
pub struct GenericEncryptingKey<D, MGD, T, M>
where
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    inner: GenericRsaPublicKey<T, M>,
    #[cfg(feature = "alloc")]
    label: Option<Box<[u8]>>,
    #[cfg(not(feature = "alloc"))]
    label: Option<Label>,
    phantom: PhantomData<D>,
    mg_phantom: PhantomData<MGD>,
}

/// Boxed OAEP encrypting key alias.
#[cfg(feature = "alloc")]
pub type EncryptingKey<D, MGD = D> = GenericEncryptingKey<D, MGD, BoxedUint, BoxedMontyParams>;

impl<D, MGD, T, M> GenericEncryptingKey<D, MGD, T, M>
where
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: GenericRsaPublicKey<T, M>) -> Self {
        Self {
            inner: key,
            label: None,
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }

    /// Create a new verifying key from an RSA public key using provided label
    #[cfg(feature = "alloc")]
    pub fn new_with_label<S: Into<Box<[u8]>>>(key: GenericRsaPublicKey<T, M>, label: S) -> Self {
        Self {
            inner: key,
            label: Some(label.into()),
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }

    /// Create a new encrypting key from an RSA public key using provided label.
    /// no_alloc counterpart that accepts a fixed-capacity [`Label`].
    #[cfg(not(feature = "alloc"))]
    pub fn new_with_label(key: GenericRsaPublicKey<T, M>, label: Label) -> Self {
        Self {
            inner: key,
            label: Some(label),
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }
}

impl<D, MGD, T, M> RandomizedEncryptor for GenericEncryptingKey<D, MGD, T, M>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    fn encrypt_with_rng_into<'a, R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        let label = self.label.as_deref();
        encrypt_digest_into::<_, D, MGD, _, T>(rng, &self.inner, msg, label, storage)
    }

    #[cfg(feature = "alloc")]
    fn encrypt_with_rng<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        let mut storage = vec![0u8; self.inner.size()];
        let ciphertext = self.encrypt_with_rng_into(rng, msg, &mut storage)?;
        Ok(ciphertext.to_vec())
    }
}

#[cfg(feature = "alloc")]
impl<D, MGD, T, M> PartialEq for GenericEncryptingKey<D, MGD, T, M>
where
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
    GenericRsaPublicKey<T, M>: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.label == other.label
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg(all(feature = "hazmat", feature = "serde", feature = "private-key"))]
    fn test_serde() {
        use super::*;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use serde_test::{assert_tokens, Configure, Token};

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key =
            crate::RsaPrivateKey::new_unchecked(&mut rng, 64).expect("failed to generate key");
        let encrypting_key = EncryptingKey::<sha2::Sha256>::new(priv_key.to_public_key());

        let tokens = [
            Token::Struct {
                name: "GenericEncryptingKey",
                len: 4,
            },
            Token::Str("inner"),
            Token::Str(
                "3024300d06092a864886f70d01010105000313003010020900ab240c3361d02e370203010001",
            ),
            Token::Str("label"),
            Token::None,
            Token::Str("phantom"),
            Token::UnitStruct {
                name: "PhantomData",
            },
            Token::Str("mg_phantom"),
            Token::UnitStruct {
                name: "PhantomData",
            },
            Token::StructEnd,
        ];
        assert_tokens(&encrypting_key.readable(), &tokens);
    }
}
