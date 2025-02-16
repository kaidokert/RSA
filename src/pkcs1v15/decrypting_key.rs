use super::{decrypt, EncryptingKey};
use crate::{
    dummy_rng::DummyRng,
    traits::{Decryptor, EncryptingKeypair, RandomizedDecryptor},
    Result, RsaPrivateKey,
};
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::traits::UnsignedModularInt;

/// Decryption key for PKCS#1 v1.5 decryption as described in [RFC8017 § 7.2].
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DecryptingKey<T>
where
    T: UnsignedModularInt,
{
    inner: RsaPrivateKey<T>,
}

impl<T> DecryptingKey<T>
where
    T: UnsignedModularInt,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPrivateKey<T>) -> Self {
        Self { inner: key }
    }
}

impl<T> Decryptor for DecryptingKey<T> where T: UnsignedModularInt {}

impl<T> RandomizedDecryptor for DecryptingKey<T> where T: UnsignedModularInt {}

impl<T> EncryptingKeypair for DecryptingKey<T>
where
    T: UnsignedModularInt,
{
    type EncryptingKey = EncryptingKey<T>;
    fn encrypting_key(&self) -> EncryptingKey<T> {
        todo!()
    }
}

impl<T> ZeroizeOnDrop for DecryptingKey<T> where T: UnsignedModularInt {}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
        use serde_test::{assert_tokens, Configure, Token};

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        /*TODO:
        let decrypting_key =
            DecryptingKey::new(RsaPrivateKey::new(&mut rng, 64).expect("failed to generate key"));

        let tokens = [
            Token::Struct { name: "DecryptingKey", len: 1 },
            Token::Str("inner"),
            Token::Str("3054020100300d06092a864886f70d01010105000440303e020100020900c9269f2f225eb38d020301000102086ecdc49f528812a1020500d2aaa725020500f46fc249020500887e253902046b4851e1020423806864"),
            Token::StructEnd,
        ];
        assert_tokens(&decrypting_key.readable(), &tokens);
         */
    }
}
