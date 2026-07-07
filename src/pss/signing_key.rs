use super::{sign_digest, GenericSigningKey, Signature, VerifyingKey};
use crate::{Result, RsaPrivateKey};
use crypto_bigint::{modular::BoxedMontyParams, BoxedUint};
use digest::{Digest, FixedOutputReset, Update};
use rand_core::{CryptoRng, TryCryptoRng};
use signature::{
    hazmat::RandomizedPrehashSigner, Keypair, RandomizedDigestSigner, RandomizedMultipartSigner,
    RandomizedSigner,
};
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "serde")]
use {
    pkcs8::DecodePrivateKey,
    serdect::serde::{de, ser, Deserialize, Serialize},
};

#[cfg(feature = "encoding")]
use {
    super::get_pss_signature_algo_id,
    crate::encoding::verify_algorithm_id,
    const_oid::AssociatedOid,
    pkcs8::{EncodePrivateKey, SecretDocument},
    spki::{
        der::AnyRef, AlgorithmIdentifierOwned, AlgorithmIdentifierRef,
        AssociatedAlgorithmIdentifier, DynSignatureAlgorithmIdentifier,
    },
};

#[cfg(feature = "getrandom")]
use {
    crypto_common::getrandom::SysRng,
    signature::{hazmat::PrehashSigner, MultipartSigner, Signer},
};

/// Signing key for producing RSASSA-PSS signatures as described in
/// [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
pub type SigningKey<D> = GenericSigningKey<D, BoxedUint, BoxedMontyParams>;

impl<D> GenericSigningKey<D, BoxedUint, BoxedMontyParams>
where
    D: Digest,
{
    /// Generate a new random RSASSA-PSS signing key.
    /// Digest output size is used as a salt length.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::random_with_salt_len(rng, bit_size, <D as Digest>::output_size())
    }

    /// Generate a new random RSASSA-PSS signing key with a salt of the given length.
    pub fn random_with_salt_len<R: CryptoRng + ?Sized>(
        rng: &mut R,
        bit_size: usize,
        salt_len: usize,
    ) -> Result<Self> {
        Ok(Self::new_with_salt_len(
            RsaPrivateKey::new(rng, bit_size)?,
            salt_len,
        ))
    }
}

//
// `*Signer` trait impls
//

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset + Update,
{
    fn try_sign_digest_with_rng<
        R: TryCryptoRng + ?Sized,
        F: Fn(&mut D) -> signature::Result<()>,
    >(
        &self,
        rng: &mut R,
        f: F,
    ) -> signature::Result<Signature> {
        let mut digest = D::new();
        f(&mut digest)?;
        sign_digest::<_, D>(rng, false, &self.inner, &digest.finalize(), self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset + Update,
{
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        self.try_sign_digest_with_rng(rng, |digest: &mut D| {
            Update::update(digest, msg);
            Ok(())
        })
    }
}

impl<D> RandomizedMultipartSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset + Update,
{
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> signature::Result<Signature> {
        self.try_sign_digest_with_rng(rng, |digest: &mut D| {
            msg.iter().for_each(|slice| Update::update(digest, slice));
            Ok(())
        })
    }
}

impl<D> RandomizedPrehashSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset + Update,
{
    fn sign_prehash_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, false, &self.inner, prehash, self.salt_len)?
            .as_slice()
            .try_into()
    }
}

#[cfg(feature = "getrandom")]
impl<D> PrehashSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        self.sign_prehash_with_rng(&mut SysRng, prehash)
    }
}

#[cfg(feature = "getrandom")]
impl<D> Signer<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        self.try_sign_with_rng(&mut SysRng, msg)
    }
}

#[cfg(feature = "getrandom")]
impl<D> MultipartSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> signature::Result<Signature> {
        self.try_multipart_sign_with_rng(&mut SysRng, msg)
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
impl<D> DynSignatureAlgorithmIdentifier for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        get_pss_signature_algo_id::<D>(self.salt_len as u8)
    }
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
    D: Digest,
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
        VerifyingKey {
            inner: self.inner.to_public_key(),
            salt_len: Some(self.salt_len),
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "encoding")]
impl<D> TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        verify_algorithm_id(&private_key_info.algorithm)?;
        RsaPrivateKey::try_from(private_key_info).map(Self::new)
    }
}

impl<D> ZeroizeOnDrop for SigningKey<D> where D: Digest {}

impl<D> PartialEq for SigningKey<D>
where
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.salt_len == other.salt_len
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
    // End-to-end KAT for the heapless-shaped `try_sign_with_rng_into`
    // wrapper on `pss::SigningKey<D>`. Exercises the full stack:
    // wrapper (which internally samples salt AND blinding `r`) →
    // `algorithms::pss::sign_with_rng_into` →
    // `rsa_private_op_and_check_blinded` → `TryRandomMod` →
    // `rsa_private_op_blinded` (InvertCt/MulCt).
    #[test]
    #[cfg(feature = "encoding")]
    fn signing_key_try_sign_with_rng_into_round_trip() {
        use super::*;
        use crate::pss::VerifyingKey;
        use pkcs1::DecodeRsaPrivateKey;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use sha2::Sha256;
        use signature::Verifier;

        const PRIV_KEY_PKCS1_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwQe5brkkpxrwR/5TJ6JXsUyBzYtbEL/w8u8P6NnxQ8sL4KYp
MzzTB6aq1gq7bieYXChg0PIWeTukGaOzZe96KxhT0GbhhYRlukktM/quRrM7nYdm
UmXo7+KWU55kfcNOjWKADL/7qmxn6y/+kPmBg83nHdr1Mq6/pNkeHY/1CeGGECl0
rg7gfEkssHjZw/uKafA271fX9A/q3LcAeWi7iA01PgmP28BrWb7OQoYVY71kFY11
e919VlMh8oXsIV0nXCkYu9dR8Pzq6U4gFASK32fFkKX/djRMljEgss3kR0SWPH7t
m5uXX1wRTJ2mRaZh/BmGweIvYCZ5y0+9ESOD1wIDAQABAoIBAAj3NuGxr8YjNi3h
3jLlE3WkvBKz+lLY13QxLmf+V3pyn+abUSaUGKkuUJkIfpQrOqRtK7IIzIps/r5C
ID8H1IDT7HCtlqQA9kikxXi4mAeoo4g5lcMWAK/Dsn/Hx5sfyzI99PyininYRyth
W02YiS96DNYSKXllLHmXrBJrcVI4FqXAz5s7MezU0XYi+jeaVGEP2bd2cHfQJki/
pLOKBvA5DGT7HbmMV7Z1qg/zcr/4Py+7qAFC5XsbQIILSMTfC45QFgs1lApnUG8H
uIhf5lgZ8m0ouDBb/e1Q04ANtdLLI6EmrR11PwavUmvPvXuedXkv2OvnuAbiJr6g
j0I0VaECgYEAyWf2QZrEoZLzVrInZ+VYtov1+jjgFcxW9lHuCJXtTx8hFla13Bmp
bc8PoxWb+37jPdrOYPW0yv1sk5VeVkxOJbms0Gn8hpyI+0muQZ3jmwlS0A10T6FL
wWECYvrxO8DCaVCQ4V+egLSDb/GMkRgHJF3Dr7g3ep7krXf2eeWILQUCgYEA9VqJ
ijMDKw/KX6swyMe3A1nA0MlLBeseXxrwNIJenwRXCzjG3BH6oHW2MGwH0EV7sSoG
FR6j7LZbp9I9NvRcAYU/s1qiAX3iX3KIsbZYNtEC6tKn/HClaHLZOhyuE8tjshyD
jhK/0rhw7R5VQ1GfJhmuzvwoMFTA0fqZBQpWZCsCgYBA5WO+3dyv50bLT5pM6uR7
5Xs7xinGPFJlCh812wFdNj2WEhiFNCuYu1hhhyv8jHUyUBehvGol4iSjJUUBb5La
qwpZGV2KDlRBDAu/Dt3w7b8mVL9+jQ144QZA2HT0ePbrsk8Mn5/V/tQ/NMjDU8ex
WxkbvLL7qskqb/YWbvRC9QKBgQDUJYvFpmQ36LhozmIpSZ6yU/oHzfWD0Y/6VhWa
oZtlTeBhwJ8aDKWz9vQonFCJQns4bgjCXDMLa4aG7p+lk9a2LdwtndF1Dr8dHrCZ
UPynsUQffTRpb5FmZd/0gnX2gafbixIpV4brkjV6of7BbaL50702Fgw99hqftVp4
ZD7c7wKBgD7uIs6rgpaJzKbf7ejjZSjfLOgHlJhtH6Nejp8KoJRsEQI1ofWyIn7D
eMjIuecwLapPwjY2G0/sUW61bqrxgW10wDJHPNllGsZFanzpb7x5o/7eNhzc4qNf
Rmb665iB5fwpqmbE/hYKIn7asYQE+V0dkgt8M3qvlJJ5JJbCrJx3
-----END RSA PRIVATE KEY-----";

        let priv_key = RsaPrivateKey::from_pkcs1_pem(PRIV_KEY_PKCS1_PEM).unwrap();
        let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
        let verifying_key = VerifyingKey::<Sha256>::new(priv_key.to_public_key());

        let msg: &[u8] = b"blinded pss sign test message";
        let mut rng = ChaCha8Rng::from_seed([42; 32]);

        // 2048-bit key → 256-byte signature and EM;
        // salt_len defaults to `Sha256::output_size()` = 32.
        let mut em_storage = [0u8; 256];
        let mut sig_storage = [0u8; 256];
        let mut salt_storage = [0u8; 32];
        let sig_slice = signing_key
            .try_sign_with_rng_into(
                &mut rng,
                msg,
                &mut em_storage,
                &mut sig_storage,
                &mut salt_storage,
            )
            .unwrap();
        assert_eq!(sig_slice.len(), 256);

        let sig = Signature::try_from(sig_slice).unwrap();
        verifying_key.verify(msg, &sig).unwrap();
    }

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
            "ad020500ccaddf17020500cb529d3d020500bb526d6f"
        ))];

        assert_tokens(&signing_key.readable(), &tokens);
    }
}
