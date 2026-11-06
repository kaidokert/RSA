#[cfg(not(feature = "alloc"))]
use super::Label;
use super::encrypt_digest_into;
use crate::traits::{
    PublicKeyParts, UnsignedModularInt,
    modular::{CtModulusParams, ModulusParams},
};
use crate::{GenericRsaPublicKey, Result, traits::RandomizedEncryptor};
#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;
#[cfg(feature = "alloc")]
use crypto_bigint::{BoxedUint, modular::BoxedMontyParams};
use digest::{Digest, FixedOutputReset};
use rand_core::TryCryptoRng;
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
    M: CtModulusParams<Modulus = T>,
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
    fn encrypt_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
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
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use crate::RsaPublicKey;
        use pkcs8::DecodePublicKey;
        use serde_test::{Configure, Token, assert_tokens};

        let der = include_bytes!("../../tests/examples/pkcs8/rsa2048-pub.der");
        let pub_key = RsaPublicKey::from_public_key_der(der).unwrap();
        let encoded = include_str!("../../tests/examples/pkcs8/rsa2048-pub.hex").trim();
        let encrypting_key = EncryptingKey::<sha2::Sha256>::new(pub_key);

        let tokens = [
            Token::Struct {
                name: "GenericEncryptingKey",
                len: 4,
            },
            Token::Str("inner"),
            Token::Str(encoded),
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
