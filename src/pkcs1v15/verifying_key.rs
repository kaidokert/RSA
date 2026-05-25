#[cfg(feature = "alloc")]
use super::pkcs1v15_generate_prefix;
#[cfg(not(feature = "alloc"))]
use super::{pkcs1v15_generate_prefix_helper, Prefix};
use super::{verify_generic, GenericSignature};
use crate::{
    key::GenericRsaPublicKey,
    traits::{modular::ModulusParams, PublicKeyParts, UnsignedModularInt},
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use const_oid::AssociatedOid;
use core::marker::PhantomData;
#[cfg(feature = "alloc")]
use crypto_bigint::{modular::BoxedMontyParams, BoxedUint};
use digest::{Digest, FixedOutput, HashMarker, Update};
use signature::{hazmat::PrehashVerifier, DigestVerifier, Verifier};

#[cfg(all(feature = "alloc", feature = "encoding"))]
use crate::key::RsaPublicKey;
#[cfg(feature = "encoding")]
use {
    super::oid,
    spki::{
        der::AnyRef, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier, Document,
        EncodePublicKey, SignatureAlgorithmIdentifier,
    },
};
#[cfg(feature = "serde")]
use {
    serdect::serde::{de, ser, Deserialize, Serialize},
    spki::DecodePublicKey,
};

/// Verifying key for `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug)]
pub struct GenericVerifyingKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    pub(super) inner: GenericRsaPublicKey<T, M>,
    #[cfg(feature = "alloc")]
    pub(super) prefix: Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub(super) prefix: Prefix,
    pub(super) phantom: PhantomData<D>,
}

/// Boxed PKCS#1 v1.5 verifying key alias.
#[cfg(feature = "alloc")]
pub type VerifyingKey<D> = GenericVerifyingKey<D, BoxedUint, BoxedMontyParams>;

impl<D, T, M> GenericVerifyingKey<D, T, M>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    /// Create a new verifying key with a prefix for the digest `D`.
    pub fn new(key: GenericRsaPublicKey<T, M>) -> Self {
        Self {
            inner: key,
            #[cfg(feature = "alloc")]
            prefix: pkcs1v15_generate_prefix::<D>(),
            #[cfg(not(feature = "alloc"))]
            prefix: pkcs1v15_generate_prefix_helper::<D>(),
            phantom: Default::default(),
        }
    }
}

impl<D, T, M> GenericVerifyingKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    /// Create a new verifying key from an RSA public key with an empty prefix.
    ///
    /// ## Note: unprefixed signatures are uncommon
    ///
    /// In most cases you'll want to use [`GenericVerifyingKey::new`] instead.
    pub fn new_unprefixed(key: GenericRsaPublicKey<T, M>) -> Self {
        Self {
            inner: key,
            #[cfg(feature = "alloc")]
            prefix: Vec::new(),
            #[cfg(not(feature = "alloc"))]
            prefix: Prefix::new(),
            phantom: Default::default(),
        }
    }

    fn verify_prehash_signature(
        &self,
        prehash: &[u8],
        signature: &GenericSignature<T>,
    ) -> signature::Result<()> {
        let mut storage = self.inner.n().as_ref().to_be_bytes();
        verify_generic(
            &self.inner,
            self.prefix.as_ref(),
            prehash,
            signature.inner(),
            storage.as_mut(),
        )
        .map_err(Into::into)
    }
}

//
// `*Verifier` trait impls
//

impl<D, T, M> DigestVerifier<D, GenericSignature<T>> for GenericVerifyingKey<D, T, M>
where
    D: Default + FixedOutput + HashMarker + Update,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    fn verify_digest<F: Fn(&mut D) -> signature::Result<()>>(
        &self,
        f: F,
        signature: &GenericSignature<T>,
    ) -> signature::Result<()> {
        let mut digest = D::default();
        f(&mut digest)?;
        self.verify_prehash_signature(&digest.finalize_fixed(), signature)
    }
}

impl<D, T, M> PrehashVerifier<GenericSignature<T>> for GenericVerifyingKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &GenericSignature<T>,
    ) -> signature::Result<()> {
        self.verify_prehash_signature(prehash, signature)
    }
}

impl<D, T, M> Verifier<GenericSignature<T>> for GenericVerifyingKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    fn verify(&self, msg: &[u8], signature: &GenericSignature<T>) -> signature::Result<()> {
        self.verify_prehash_signature(&D::digest(msg), signature)
    }
}

//
// Other trait impls
//

impl<D, T, M> AsRef<GenericRsaPublicKey<T, M>> for GenericVerifyingKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    fn as_ref(&self) -> &GenericRsaPublicKey<T, M> {
        &self.inner
    }
}

#[cfg(feature = "encoding")]
#[cfg(feature = "alloc")]
impl<D> AssociatedAlgorithmIdentifier for VerifyingKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

// Implemented manually so we don't have to bind D with Clone
impl<D, T, M> Clone for GenericVerifyingKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            prefix: self.prefix.clone(),
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "encoding")]
#[cfg(feature = "alloc")]
impl<D> EncodePublicKey for VerifyingKey<D>
where
    D: Digest,
{
    fn to_public_key_der(&self) -> spki::Result<Document> {
        self.inner.to_public_key_der()
    }
}

impl<D, T, M> From<GenericRsaPublicKey<T, M>> for GenericVerifyingKey<D, T, M>
where
    D: Digest + AssociatedOid,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    fn from(key: GenericRsaPublicKey<T, M>) -> Self {
        Self::new(key)
    }
}

impl<D, T, M> From<GenericVerifyingKey<D, T, M>> for GenericRsaPublicKey<T, M>
where
    D: Digest,
    T: UnsignedModularInt,
    M: ModulusParams<Modulus = T>,
{
    fn from(key: GenericVerifyingKey<D, T, M>) -> Self {
        key.inner
    }
}

#[cfg(feature = "encoding")]
#[cfg(feature = "alloc")]
impl<D> SignatureAlgorithmIdentifier for VerifyingKey<D>
where
    D: Digest + oid::RsaSignatureAssociatedOid,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> =
        AlgorithmIdentifierRef {
            oid: D::OID,
            parameters: Some(AnyRef::NULL),
        };
}

#[cfg(feature = "encoding")]
#[cfg(feature = "alloc")]
impl<D> TryFrom<pkcs8::SubjectPublicKeyInfoRef<'_>> for VerifyingKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        spki.algorithm.assert_algorithm_oid(pkcs1::ALGORITHM_OID)?;

        RsaPublicKey::try_from(spki).map(Self::new)
    }
}

impl<D, T, M> PartialEq for GenericVerifyingKey<D, T, M>
where
    D: Digest,
    T: UnsignedModularInt + PartialEq,
    M: ModulusParams<Modulus = T>,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.prefix == other.prefix
    }
}

#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
impl<D> Serialize for VerifyingKey<D>
where
    D: Digest,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let der = self.to_public_key_der().map_err(ser::Error::custom)?;
        serdect::slice::serialize_hex_lower_or_bin(&der, serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
impl<'de, D> Deserialize<'de> for VerifyingKey<D>
where
    D: Digest + AssociatedOid,
{
    fn deserialize<De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: serde::Deserializer<'de>,
    {
        let der_bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::from_public_key_der(&der_bytes).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(feature = "hazmat", feature = "serde"))]
    fn test_serde() {
        use super::*;
        use crate::RsaPrivateKey;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use serde_test::{assert_tokens, Configure, Token};
        use sha2::Sha256;

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key = RsaPrivateKey::new_unchecked(&mut rng, 64).expect("failed to generate key");
        let pub_key = priv_key.to_public_key();
        let verifying_key = GenericVerifyingKey::<Sha256, _, _>::new(pub_key);

        let tokens = [Token::Str(
            "3024300d06092a864886f70d01010105000313003010020900ab240c3361d02e370203010001",
        )];

        assert_tokens(&verifying_key.readable(), &tokens);
    }
}
