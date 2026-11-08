use super::encrypt_into;
use crate::{
    Result,
    public_key::GenericRsaPublicKey,
    traits::{
        PublicKeyParts, RandomizedEncryptor, UnsignedModularInt,
        modular::{CtModulusParams, ModulusParams},
    },
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use crypto_bigint::{BoxedUint, modular::BoxedMontyParams};
use rand_core::TryCryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.2].
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "GenericRsaPublicKey<T, M>: Serialize",
        deserialize = "GenericRsaPublicKey<T, M>: serde::de::DeserializeOwned"
    ))
)]
pub struct GenericEncryptingKey<T, M>
where
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    pub(super) inner: GenericRsaPublicKey<T, M>,
}

/// Boxed PKCS#1 v1.5 encrypting key alias.
#[cfg(feature = "alloc")]
pub type EncryptingKey = GenericEncryptingKey<BoxedUint, BoxedMontyParams>;

impl<T, M> GenericEncryptingKey<T, M>
where
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    /// Create a new encrypting key from an RSA public key.
    pub fn new(key: GenericRsaPublicKey<T, M>) -> Self {
        Self { inner: key }
    }
}

impl<T, M> RandomizedEncryptor for GenericEncryptingKey<T, M>
where
    T: UnsignedModularInt,
    M: CtModulusParams<Modulus = T>,
{
    fn encrypt_with_rng_into<'a, R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        encrypt_into(rng, &self.inner, msg, storage)
    }

    #[cfg(feature = "alloc")]
    fn encrypt_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        let mut storage = vec![0u8; self.inner.size()];
        let ciphertext = encrypt_into(rng, &self.inner, msg, &mut storage)?;
        Ok(ciphertext.to_vec())
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
        let encrypting_key = GenericEncryptingKey::new(pub_key);

        let tokens = [
            Token::Struct {
                name: "GenericEncryptingKey",
                len: 1,
            },
            Token::Str("inner"),
            Token::Str(encoded),
            Token::StructEnd,
        ];
        assert_tokens(&encrypting_key.clone().readable(), &tokens);
    }
}
