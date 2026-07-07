use super::encrypt_into;
use crate::{
    key::GenericRsaPublicKey,
    traits::{
        modular::{CtModulusParams, ModulusParams},
        PublicKeyParts, RandomizedEncryptor, UnsignedModularInt,
    },
    Result,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use crypto_bigint::{modular::BoxedMontyParams, BoxedUint};
use rand_core::CryptoRng;
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
    fn encrypt_with_rng_into<'a, R: rand_core::TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        encrypt_into(rng, &self.inner, msg, storage)
    }

    #[cfg(feature = "alloc")]
    fn encrypt_with_rng<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        let mut storage = vec![0u8; self.inner.size()];
        let ciphertext = encrypt_into(rng, &self.inner, msg, &mut storage)?;
        Ok(ciphertext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(feature = "hazmat", feature = "serde", feature = "keygen"))]
    fn test_serde() {
        use super::*;
        use crate::RsaPrivateKey;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use serde_test::{assert_tokens, Configure, Token};

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key = RsaPrivateKey::new_unchecked(&mut rng, 64).expect("failed to generate key");
        let encrypting_key = GenericEncryptingKey::new(priv_key.to_public_key());

        let tokens = [
            Token::Struct {
                name: "GenericEncryptingKey",
                len: 1,
            },
            Token::Str("inner"),
            Token::Str(
                "3024300d06092a864886f70d01010105000313003010020900ab240c3361d02e370203010001",
            ),
            Token::StructEnd,
        ];
        assert_tokens(&encrypting_key.clone().readable(), &tokens);
    }
}
