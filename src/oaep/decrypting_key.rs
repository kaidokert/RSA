use super::decrypt_digest;
use crate::{
    dummy_rng::DummyRng,
    traits::{Decryptor, RandomizedDecryptor},
    Result, RsaPrivateKey,
};
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::algorithms::oaep::Label;
use crate::traits::UnsignedModularInt;

/// Decryption key for PKCS#1 v1.5 decryption as described in [RFC8017 § 7.1].
///
/// [RFC8017 § 7.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DecryptingKey<T, D, MGD = D>
where
    T: UnsignedModularInt,
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    inner: RsaPrivateKey<T>,
    label: Option<Label>,
    phantom: PhantomData<D>,
    mg_phantom: PhantomData<MGD>,
}

impl<T, D, MGD> DecryptingKey<T, D, MGD>
where
    T: UnsignedModularInt,
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPrivateKey<T>) -> Self {
        Self {
            inner: key,
            label: None,
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }

    /// Create a new verifying key from an RSA public key using provided label
    pub fn new_with_label<S: AsRef<str>>(key: RsaPrivateKey<T>, label: S) -> Self {
        Self {
            inner: key,
            label: Some(label.as_ref().into()),
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }
}

impl<T, D, MGD> Decryptor for DecryptingKey<T, D, MGD>
where
    T: UnsignedModularInt,
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
}

impl<T, D, MGD> RandomizedDecryptor for DecryptingKey<T, D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
}

impl<T, D, MGD> ZeroizeOnDrop for DecryptingKey<T, D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
    T: UnsignedModularInt,
{
}

impl<T, D, MGD> PartialEq for DecryptingKey<T, D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
    T: UnsignedModularInt,
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
        use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
        use serde_test::{assert_tokens, Configure, Token};
        use sha2::Sha256;

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        /* TODO:
        let decrypting_key = DecryptingKey::<Sha256>::new(
            RsaPrivateKey::new(&mut rng, 64).expect("failed to generate key"),
        );

        let tokens = [
            Token::Struct { name: "DecryptingKey", len: 4 },
            Token::Str("inner"),
            Token::Str("3054020100300d06092a864886f70d01010105000440303e020100020900c9269f2f225eb38d020301000102086ecdc49f528812a1020500d2aaa725020500f46fc249020500887e253902046b4851e1020423806864"),
            Token::Str("label"),
            Token::None,
            Token::Str("phantom"),
            Token::UnitStruct { name: "PhantomData", },
            Token::Str("mg_phantom"),
            Token::UnitStruct { name: "PhantomData", },
            Token::StructEnd,
        ];
        assert_tokens(&decrypting_key.readable(), &tokens);
        */
    }
}
