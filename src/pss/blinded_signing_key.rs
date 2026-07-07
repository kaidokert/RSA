use super::{sign_digest, Signature, SigningKey, VerifyingKey};
use crate::{Result, RsaPrivateKey};
use digest::{Digest, FixedOutputReset, HashMarker, Update};
use rand_core::{CryptoRng, TryCryptoRng};
use signature::{
    hazmat::RandomizedPrehashSigner, Keypair, RandomizedDigestSigner, RandomizedMultipartSigner,
    RandomizedSigner,
};
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "encoding")]
use {
    super::get_pss_signature_algo_id,
    const_oid::AssociatedOid,
    pkcs8::{EncodePrivateKey, SecretDocument},
    spki::{
        der::AnyRef, AlgorithmIdentifierOwned, AlgorithmIdentifierRef,
        AssociatedAlgorithmIdentifier, DynSignatureAlgorithmIdentifier,
    },
};
#[cfg(feature = "serde")]
use {
    pkcs8::DecodePrivateKey,
    serdect::serde::{de, ser, Deserialize, Serialize},
};

/// Signing key for producing "blinded" RSASSA-PSS signatures as described in
/// [draft-irtf-cfrg-rsa-blind-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/).
#[derive(Debug, Clone)]
pub struct BlindedSigningKey<D>(SigningKey<D>)
where
    D: Digest;

impl<D> BlindedSigningKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self(SigningKey::new(key))
    }

    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey, salt_len: usize) -> Self {
        Self(SigningKey::new_with_salt_len(key, salt_len))
    }

    /// Create a new random RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    /// Digest output size is used as a salt length.
    #[cfg(feature = "keygen")]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        SigningKey::random(rng, bit_size).map(Self)
    }

    /// Create a new random RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
    #[cfg(feature = "keygen")]
    pub fn random_with_salt_len<R: CryptoRng + ?Sized>(
        rng: &mut R,
        bit_size: usize,
        salt_len: usize,
    ) -> Result<Self> {
        SigningKey::random_with_salt_len(rng, bit_size, salt_len).map(Self)
    }

    /// Return specified salt length for this key
    pub fn salt_len(&self) -> usize {
        self.0.salt_len()
    }
}

//
// `*Signer` trait impls
//

impl<D> RandomizedSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        self.try_multipart_sign_with_rng(rng, &[msg])
    }
}

impl<D> RandomizedMultipartSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> signature::Result<Signature> {
        let mut digest = D::new();
        msg.iter()
            .for_each(|slice| <D as Digest>::update(&mut digest, slice));
        sign_digest::<_, D>(
            rng,
            true,
            self.0.as_ref(),
            &digest.finalize(),
            self.0.salt_len(),
        )?
        .as_slice()
        .try_into()
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for BlindedSigningKey<D>
where
    D: Default + FixedOutputReset + HashMarker + Update,
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
        sign_digest::<_, D>(
            rng,
            true,
            self.0.as_ref(),
            &digest.finalize(),
            self.0.salt_len(),
        )?
        .as_slice()
        .try_into()
    }
}

impl<D> RandomizedPrehashSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, true, self.0.as_ref(), prehash, self.0.salt_len())?
            .as_slice()
            .try_into()
    }
}

//
// Other trait impls
//

impl<D> AsRef<RsaPrivateKey> for BlindedSigningKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPrivateKey {
        self.0.as_ref()
    }
}

#[cfg(feature = "encoding")]
impl<D> AssociatedAlgorithmIdentifier for BlindedSigningKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

#[cfg(feature = "encoding")]
impl<D> DynSignatureAlgorithmIdentifier for BlindedSigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        get_pss_signature_algo_id::<D>(self.0.salt_len() as u8)
    }
}

#[cfg(feature = "encoding")]
impl<D> EncodePrivateKey for BlindedSigningKey<D>
where
    D: Digest,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        self.0.to_pkcs8_der()
    }
}

impl<D> From<RsaPrivateKey> for BlindedSigningKey<D>
where
    D: Digest,
{
    fn from(key: RsaPrivateKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<BlindedSigningKey<D>> for RsaPrivateKey
where
    D: Digest,
{
    fn from(key: BlindedSigningKey<D>) -> Self {
        key.0.into()
    }
}

impl<D> Keypair for BlindedSigningKey<D>
where
    D: Digest,
{
    type VerifyingKey = VerifyingKey<D>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        Keypair::verifying_key(&self.0)
    }
}

#[cfg(feature = "encoding")]
impl<D> TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for BlindedSigningKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        SigningKey::try_from(private_key_info).map(Self)
    }
}

impl<D> ZeroizeOnDrop for BlindedSigningKey<D> where D: Digest {}

impl<D> PartialEq for BlindedSigningKey<D>
where
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(feature = "serde")]
impl<D> Serialize for BlindedSigningKey<D>
where
    D: Digest,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let der = self.to_pkcs8_der().map_err(ser::Error::custom)?;
        serdect::slice::serialize_hex_lower_or_bin(&der.as_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, D> Deserialize<'de> for BlindedSigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn deserialize<De>(deserializer: De) -> core::result::Result<Self, De::Error>
    where
        De: serde::Deserializer<'de>,
    {
        let der_bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::from_pkcs8_der(&der_bytes).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(feature = "hazmat", feature = "serde", feature = "keygen"))]
    fn test_serde() {
        use super::*;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use serde_test::{assert_tokens, Configure, Token};
        use sha2::Sha256;

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = BlindedSigningKey::<Sha256>::new(
            RsaPrivateKey::new_unchecked(&mut rng, 64).expect("failed to generate key"),
        );

        let tokens = [Token::Str(concat!(
            "3056020100300d06092a864886f70d010101050004423040020100020900ab240c",
            "3361d02e370203010001020811e54a15259d22f9020500ceff5cf3020500d3a7aa",
            "ad020500ccaddf17020500cb529d3d020500bb526d6f"
        ))];
        assert_tokens(&signing_key.readable(), &tokens);
    }
}
