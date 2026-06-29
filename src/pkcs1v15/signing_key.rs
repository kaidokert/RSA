//! Boxed RSASSA-PKCS1-v1_5 signing key — alloc-side type alias and
//! specializations over [`super::GenericSigningKey`]. Mirrors the
//! pattern on the verify side (`verifying_key.rs`).
//!
//! The struct, generic constructors (`new`, `new_unprefixed`), `Clone`,
//! `Debug`, `AsRef<GenericRsaPrivateKey<T, M>>`, `Zeroize`, and the
//! `try_sign_into` family all live on [`super::GenericSigningKey`].
//! This file holds only what's tied to the boxed substitution:
//! keygen-bearing constructors, the `signature::*Signer` trait
//! family (which delegates to the alloc-side `sign(...)`), encoding,
//! serde, and the legacy `Keypair` wiring.

use super::{sign, GenericSigningKey, GenericVerifyingKey, Signature, VerifyingKey};
use crate::{dummy_rng::DummyRng, Result, RsaPrivateKey};
use const_oid::AssociatedOid;
use crypto_bigint::{modular::BoxedMontyParams, BoxedUint};
use digest::{Digest, FixedOutput, HashMarker, Update};
use rand_core::{CryptoRng, TryCryptoRng};
use signature::{
    hazmat::PrehashSigner, DigestSigner, Keypair, MultipartSigner, RandomizedDigestSigner,
    RandomizedMultipartSigner, RandomizedSigner, Signer,
};
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "encoding")]
use {
    super::oid,
    pkcs8::{EncodePrivateKey, SecretDocument},
    spki::{
        der::AnyRef, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
        SignatureAlgorithmIdentifier,
    },
};
#[cfg(feature = "serde")]
use {
    pkcs8::DecodePrivateKey,
    serdect::serde::{de, ser, Deserialize, Serialize},
};

/// Signing key for `RSASSA-PKCS1-v1_5` signatures as described in
/// [RFC8017 § 8.2]. Boxed alias over [`GenericSigningKey`] — equivalent
/// to `GenericSigningKey<D, BoxedUint, BoxedMontyParams>`.
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
pub type SigningKey<D> = GenericSigningKey<D, BoxedUint, BoxedMontyParams>;

impl<D> GenericSigningKey<D, BoxedUint, BoxedMontyParams>
where
    D: Digest + AssociatedOid,
{
    /// Generate a fresh RSA key pair of the given bit size, then wrap
    /// it in a signing key with the DigestInfo prefix for `D`.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Ok(Self::new(RsaPrivateKey::new(rng, bit_size)?))
    }
}

impl<D> GenericSigningKey<D, BoxedUint, BoxedMontyParams>
where
    D: Digest,
{
    /// Generate a fresh RSA key pair of the given bit size with an empty
    /// prefix (raw signatures, no DigestInfo wrapper).
    pub fn random_unprefixed<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Ok(Self::new_unprefixed(RsaPrivateKey::new(rng, bit_size)?))
    }
}

//
// `*Signer` trait impls
//

impl<D> DigestSigner<D, Signature> for SigningKey<D>
where
    D: Default + FixedOutput + HashMarker + Update,
{
    fn try_sign_digest<F: Fn(&mut D) -> signature::Result<()>>(
        &self,
        f: F,
    ) -> signature::Result<Signature> {
        let mut digest = D::default();
        f(&mut digest)?;
        sign::<DummyRng>(None, &self.inner, &self.prefix, &digest.finalize_fixed())?
            .as_slice()
            .try_into()
    }
}

impl<D> PrehashSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        sign::<DummyRng>(None, &self.inner, &self.prefix, prehash)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey<D>
where
    D: Default + FixedOutput + HashMarker + Update,
{
    fn try_sign_digest_with_rng<
        R: TryCryptoRng + ?Sized,
        F: Fn(&mut D) -> signature::Result<()>,
    >(
        &self,
        rng: &mut R,
        f: F,
    ) -> signature::Result<Signature> {
        let mut digest = D::default();
        f(&mut digest)?;
        sign(
            Some(rng),
            &self.inner,
            &self.prefix,
            &digest.finalize_fixed(),
        )?
        .as_slice()
        .try_into()
    }
}

impl<D> RandomizedSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        self.try_multipart_sign_with_rng(rng, &[msg])
    }
}

impl<D> RandomizedMultipartSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> signature::Result<Signature> {
        let mut digest = D::new();
        msg.iter().for_each(|slice| digest.update(slice));
        sign(Some(rng), &self.inner, &self.prefix, &digest.finalize())?
            .as_slice()
            .try_into()
    }
}

impl<D> Signer<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        self.try_multipart_sign(&[msg])
    }
}

impl<D> MultipartSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> signature::Result<Signature> {
        let mut digest = D::new();
        msg.iter().for_each(|slice| digest.update(slice));
        sign::<DummyRng>(None, &self.inner, &self.prefix, &digest.finalize())?
            .as_slice()
            .try_into()
    }
}

//
// Other trait impls
//

#[cfg(feature = "encoding")]
impl<D> AssociatedAlgorithmIdentifier for SigningKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

#[cfg(feature = "encoding")]
impl<D> EncodePrivateKey for SigningKey<D>
where
    D: Digest,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        self.inner.to_pkcs8_der()
    }
}

impl<D> From<RsaPrivateKey> for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn from(key: RsaPrivateKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<SigningKey<D>> for RsaPrivateKey
where
    D: Digest,
{
    fn from(key: SigningKey<D>) -> Self {
        key.inner
    }
}

impl<D> Keypair for SigningKey<D>
where
    D: Digest,
{
    type VerifyingKey = VerifyingKey<D>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        GenericVerifyingKey {
            inner: self.inner.to_public_key(),
            prefix: self.prefix.clone(),
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "encoding")]
impl<D> SignatureAlgorithmIdentifier for SigningKey<D>
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
impl<D> TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        private_key_info
            .algorithm
            .assert_algorithm_oid(pkcs1::ALGORITHM_OID)?;
        RsaPrivateKey::try_from(private_key_info).map(Self::new)
    }
}

impl<D> ZeroizeOnDrop for SigningKey<D> where D: Digest {}

impl<D> PartialEq for SigningKey<D>
where
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.prefix == other.prefix
    }
}

#[cfg(feature = "serde")]
impl<D> Serialize for SigningKey<D>
where
    D: Digest,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        let der = self.to_pkcs8_der().map_err(ser::Error::custom)?;
        serdect::slice::serialize_hex_lower_or_bin(&der.as_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, D> Deserialize<'de> for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn deserialize<De>(deserializer: De) -> core::result::Result<Self, De::Error>
    where
        De: serdect::serde::Deserializer<'de>,
    {
        let der_bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::from_pkcs8_der(&der_bytes).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(feature = "hazmat", feature = "serde"))]
    fn test_serde() {
        use super::*;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use serde_test::{assert_tokens, Configure, Token};
        use sha2::Sha256;

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key = RsaPrivateKey::new_unchecked(&mut rng, 64).expect("failed to generate key");
        let signing_key = SigningKey::<Sha256>::new(priv_key);

        let tokens = [Token::Str(concat!(
            "3056020100300d06092a864886f70d010101050004423040020100020900ab240c",
            "3361d02e370203010001020811e54a15259d22f9020500ceff5cf3020500d3a7aa",
            "ad020500ccaddf17020500cb529d3d020500bb526d6f",
        ))];

        assert_tokens(&signing_key.readable(), &tokens);
    }
}
