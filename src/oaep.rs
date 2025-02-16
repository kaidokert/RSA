//! Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#oaep-encryption).

mod decrypting_key;
mod encrypting_key;

pub use self::{decrypting_key::DecryptingKey, encrypting_key::EncryptingKey};

use core::fmt;

use digest::{Digest, DynDigest, FixedOutputReset};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::algorithms::oaep::*;
use crate::algorithms::pad::{uint_to_be_pad, uint_to_zeroizing_be_pad};
use crate::algorithms::rsa::{rsa_decrypt_and_check, rsa_encrypt};
use crate::errors::{Error, Result};
use crate::key::{self, RsaPrivateKey, RsaPublicKey};
use crate::traits::{PaddingScheme, PublicKeyParts};

use crate::traits::UnsignedModularInt;
use heapless::String;

use core::marker::PhantomData;

/// Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
///
/// - `digest` is used to hash the label. The maximum possible plaintext length is `m = k - 2 * h_len - 2`,
///   where `k` is the size of the RSA modulus.
/// - `mgf_digest` specifies the hash function that is used in the [MGF1](https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2).
/// - `label` is optional data that can be associated with the message.
///
/// The two hash functions can, but don't need to be the same.
///
/// A prominent example is the [`AndroidKeyStore`](https://developer.android.com/guide/topics/security/cryptography#oaep-mgf1-digest).
/// It uses SHA-1 for `mgf_digest` and a user-chosen SHA flavour for `digest`.
pub struct Oaep {
    /// Digest type to use.
    pub digest: PhantomData<u8>, // Box<dyn DynDigest + Send + Sync>,

    /// Digest to use for Mask Generation Function (MGF).
    pub mgf_digest: PhantomData<u8>, //Box<dyn DynDigest + Send + Sync>,

    /// Optional label.
    pub label: Option<Label>,
}

impl Oaep {
    /// Create a new OAEP `PaddingScheme`, using `T` as the hash function for both the default (empty) label and for MGF1.
    ///
    pub fn new<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        Self {
            digest: Default::default(),     //Box::new(T::new()),
            mgf_digest: Default::default(), //Box::new(T::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme` with an associated `label`, using `T` as the hash function for both the label and for MGF1.
    pub fn new_with_label<T: 'static + Digest + DynDigest + Send + Sync, S: AsRef<str>>(
        label: S,
    ) -> Self {
        Self {
            digest: Default::default(),     // Box::new(T::new()),
            mgf_digest: Default::default(), //Box::new(T::new()),
            label: None,                    // Some(label.as_ref().to_string()),
        }
    }

    /// Create a new OAEP `PaddingScheme`, using `T` as the hash function for the default (empty) label, and `U` as the hash function for MGF1.
    /// If a label is needed use `PaddingScheme::new_oaep_with_label` or `PaddingScheme::new_oaep_with_mgf_hash_with_label`.
    ///
    pub fn new_with_mgf_hash<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
    >() -> Self {
        Self {
            digest: Default::default(),     // Box::new(T::new()),
            mgf_digest: Default::default(), // Box::new(U::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme` with an associated `label`, using `T` as the hash function for the label, and `U` as the hash function for MGF1.
    pub fn new_with_mgf_hash_and_label<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
        S: AsRef<str>,
    >(
        label: S,
    ) -> Self {
        Self {
            digest: Default::default(),     // Box::new(T::new()),
            mgf_digest: Default::default(), // Box::new(U::new()),
            label: None,                    //Some(label.as_ref().to_string()),
        }
    }
}

impl<T> PaddingScheme<T> for Oaep
where
    T: UnsignedModularInt,
{
    fn encrypt<'a, Rng: CryptoRngCore>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey<T>,
        msg: &[u8],
        storage: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        todo!()
        /*
        encrypt(
            rng,
            pub_key,
            msg,
            &mut *self.digest,
            &mut *self.mgf_digest,
            self.label,
            storage,
        )
         */
    }
}

impl fmt::Debug for Oaep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAEP")
            .field("digest", &"...")
            .field("mgf_digest", &"...")
            .field("label", &self.label)
            .finish()
    }
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
fn encrypt<'a, T, R: CryptoRngCore + ?Sized, D>(
    rng: &mut R,
    pub_key: &RsaPublicKey<T>,
    msg: &[u8],
    digest: &mut D,
    mgf_digest: &mut D,
    label: Option<Label>,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    T: UnsignedModularInt,
    D: Digest + FixedOutputReset,
{
    key::check_public(pub_key)?;

    let em = oaep_encrypt(rng, msg, digest, mgf_digest, label, pub_key.size(), storage)?;

    todo!()
    //let int = Zeroizing::new(BigUint::from_bytes_be(&em));
    //uint_to_be_pad(rsa_encrypt(pub_key, &int)?, pub_key.size())
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
fn encrypt_digest<'a, T, R: CryptoRngCore + ?Sized, D: Digest, MGD: Digest + FixedOutputReset>(
    rng: &mut R,
    pub_key: &RsaPublicKey<T>,
    msg: &[u8],
    label: Option<Label>,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    T: UnsignedModularInt,
{
    key::check_public(pub_key)?;

    let em = oaep_encrypt_digest::<_, D, MGD>(rng, msg, label, pub_key.size(), storage)?;

    todo!()
    //let int = Zeroizing::new(BigUint::from_bytes_be(&em));
    //uint_to_be_pad(rsa_encrypt(pub_key, &int)?, pub_key.size())
}

/// Decrypts a plaintext using RSA and the padding scheme from [PKCS#1 OAEP].
///
/// If an `rng` is passed, it uses RSA blinding to avoid timing side-channel attacks.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key.
///
/// See `decrypt_session_key` for a way of solving this problem.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
fn decrypt<'a, T, R: CryptoRngCore + ?Sized, D>(
    rng: Option<&mut R>,
    priv_key: &RsaPrivateKey<T>,
    ciphertext: &[u8],
    digest: &mut D,
    mgf_digest: &mut D,
    label: Option<Label>,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    T: UnsignedModularInt,
    D: Digest + FixedOutputReset,
{
    todo!()
}

/// Decrypts a plaintext using RSA and the padding scheme from [PKCS#1 OAEP].
///
/// If an `rng` is passed, it uses RSA blinding to avoid timing side-channel attacks.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key.
///
/// See `decrypt_session_key` for a way of solving this problem.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
fn decrypt_digest<'a, T, R: CryptoRngCore + ?Sized, D, MGD: Digest + FixedOutputReset>(
    rng: Option<&mut R>,
    priv_key: &RsaPrivateKey<T>,
    ciphertext: &[u8],
    label: Option<Label>,
) -> Result<&'a [u8]>
where
    T: UnsignedModularInt,
    D: Digest + FixedOutputReset,
{
    todo!()
}

#[cfg(test)]
mod tests {
    use crate::key::{RsaPrivateKey, RsaPublicKey};
    use crate::oaep::{EncryptingKey, Oaep};
    use crate::traits::{Decryptor, RandomizedDecryptor, RandomizedEncryptor};
    use crate::traits::{PublicKeyParts, UnsignedModularInt};

    use digest::{Digest, DynDigest, FixedOutputReset};
    use num_traits::FromPrimitive;
    use proptest::strategy::NewTree;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha8Rng,
    };
    use sha1::Sha1;
    use sha2::{Sha224, Sha256, Sha384, Sha512};
    use sha3::{Sha3_256, Sha3_384, Sha3_512};

    fn get_private_key<T: UnsignedModularInt>() -> RsaPrivateKey<T> {
        // -----BEGIN RSA PRIVATE KEY-----
        // MIIEpAIBAAKCAQEA05e4TZikwmE47RtpWoEG6tkdVTvwYEG2LT/cUKBB4iK49FKW
        // icG4LF5xVU9d1p+i9LYVjPDb61eBGg/DJ+HyjnT+dNO8Fmweq9wbi1e5NMqL5bAL
        // TymXW8yZrK9BW1m7KKZ4K7QaLDwpdrPBjbre9i8AxrsiZkAJUJbAzGDSL+fvmH11
        // xqgbENlr8pICivEQ3HzBu8Q9Iq2rN5oM1dgHjMeA/1zWIJ3qNMkiz3hPdxfkKNdb
        // WuyP8w5fAUFRB2bi4KuNRzyE6HELK5gifD2wlTN600UvGeK5v7zN2BSKv2d2+lUn
        // debnWVbkUimuWpxGlJurHmIvDkj1ZSSoTtNIOwIDAQABAoIBAQDE5wxokWLJTGYI
        // KBkbUrTYOSEV30hqmtvoMeRY1zlYMg3Bt1VFbpNwHpcC12+wuS+Q4B0f4kgVMoH+
        // eaqXY6kvrmnY1+zRRN4p+hNb0U+Vc+NJ5FAx47dpgvWDADgmxVLomjl8Gga9IWNI
        // hjDZLowrtkPXq+9wDaldaFyUFImkb1S1MW9itdLDp/G70TTLNzU6RGg/3J2V02RY
        // 3iL2xEBX/nSgpDbEMI9z9NpC81xHrBanE41IOvyR5B3DoRJzguDA9RGbAiG0/GOd
        // a5w4F3pt6bUm69iMONeYLAf5ig79h31Qiq4nW5RpFcAuLhEG0XXXTsZ3f16A0SwF
        // PZx74eNBAoGBAPgnu/OkGHfHzFmuv0LtSynDLe/LjtloY9WwkKBaiTDdYkohydz5
        // g4Vo/foN9luEYqXyrJE9bFb5dVMr2OePsHvUBcqZpIS89Z8Bm73cs5M/K85wYwC0
        // 97EQEgxd+QGBWQZ8NdowYaVshjWlK1QnOzEnG0MR8Hld9gIeY1XhpC5hAoGBANpI
        // F84Aid028q3mo/9BDHPsNL8bT2vaOEMb/t4RzvH39u+nDl+AY6Ox9uFylv+xX+76
        // CRKgMluNH9ZaVZ5xe1uWHsNFBy4OxSA9A0QdKa9NZAVKBFB0EM8dp457YRnZCexm
        // 5q1iW/mVsnmks8W+fYlc18W5xMSX/ecwkW/NtOQbAoGAHabpz4AhKFbodSLrWbzv
        // CUt4NroVFKdjnoodjfujfwJFF2SYMV5jN9LG3lVCxca43ulzc1tqka33Nfv8TBcg
        // WHuKQZ5ASVgm5VwU1wgDMSoQOve07MWy/yZTccTc1zA0ihDXgn3bfR/NnaVh2wlh
        // CkuI92eyW1494hztc7qlmqECgYEA1zenyOQ9ChDIW/ABGIahaZamNxsNRrDFMl3j
        // AD+cxHSRU59qC32CQH8ShRy/huHzTaPX2DZ9EEln76fnrS4Ey7uLH0rrFl1XvT6K
        // /timJgLvMEvXTx/xBtUdRN2fUqXtI9odbSyCtOYFL+zVl44HJq2UzY4pVRDrNcxs
        // SUkQJqsCgYBSaNfPBzR5rrstLtTdZrjImRW1LRQeDEky9WsMDtCTYUGJTsTSfVO8
        // hkU82MpbRVBFIYx+GWIJwcZRcC7OCQoV48vMJllxMAAjqG/p00rVJ+nvA7et/nNu
        // BoB0er/UmDm4Ly/97EO9A0PKMOE5YbMq9s3t3RlWcsdrU7dvw+p2+A==
        // -----END RSA PRIVATE KEY-----

        todo!()
    }

    #[test]
    #[ignore]
    fn test_encrypt_decrypt_oaep() {
        let priv_key = get_private_key::<u32>();
        do_test_encrypt_decrypt_oaep::<_, Sha1>(&priv_key);
        do_test_encrypt_decrypt_oaep::<_, Sha224>(&priv_key);
        do_test_encrypt_decrypt_oaep::<_, Sha256>(&priv_key);
        do_test_encrypt_decrypt_oaep::<_, Sha384>(&priv_key);
        do_test_encrypt_decrypt_oaep::<_, Sha512>(&priv_key);
        do_test_encrypt_decrypt_oaep::<_, Sha3_256>(&priv_key);
        do_test_encrypt_decrypt_oaep::<_, Sha3_384>(&priv_key);
        do_test_encrypt_decrypt_oaep::<_, Sha3_512>(&priv_key);

        do_test_oaep_with_different_hashes::<_, Sha1, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes::<_, Sha224, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes::<_, Sha256, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes::<_, Sha384, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes::<_, Sha512, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes::<_, Sha3_256, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes::<_, Sha3_384, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes::<_, Sha3_512, Sha1>(&priv_key);
    }

    fn get_label(rng: &mut ChaCha8Rng) -> Option<String> {
        todo!()
    }

    fn do_test_encrypt_decrypt_oaep<
        T: UnsignedModularInt,
        D: 'static + Digest + DynDigest + Send + Sync,
    >(
        prk: &RsaPrivateKey<T>,
    ) {
        todo!()
    }

    fn do_test_oaep_with_different_hashes<
        T: UnsignedModularInt,
        D: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
    >(
        prk: &RsaPrivateKey<T>,
    ) {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_decrypt_oaep_invalid_hash() {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_encrypt_decrypt_oaep_traits() {
        let priv_key = get_private_key::<u32>();
        do_test_encrypt_decrypt_oaep_traits::<_, Sha1>(&priv_key);
        do_test_encrypt_decrypt_oaep_traits::<_, Sha224>(&priv_key);
        do_test_encrypt_decrypt_oaep_traits::<_, Sha256>(&priv_key);
        do_test_encrypt_decrypt_oaep_traits::<_, Sha384>(&priv_key);
        do_test_encrypt_decrypt_oaep_traits::<_, Sha512>(&priv_key);
        do_test_encrypt_decrypt_oaep_traits::<_, Sha3_256>(&priv_key);
        do_test_encrypt_decrypt_oaep_traits::<_, Sha3_384>(&priv_key);
        do_test_encrypt_decrypt_oaep_traits::<_, Sha3_512>(&priv_key);

        do_test_oaep_with_different_hashes_traits::<_, Sha1, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes_traits::<_, Sha224, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes_traits::<_, Sha256, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes_traits::<_, Sha384, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes_traits::<_, Sha512, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes_traits::<_, Sha3_256, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes_traits::<_, Sha3_384, Sha1>(&priv_key);
        do_test_oaep_with_different_hashes_traits::<_, Sha3_512, Sha1>(&priv_key);
    }

    fn do_test_encrypt_decrypt_oaep_traits<T: UnsignedModularInt, D: Digest + FixedOutputReset>(
        prk: &RsaPrivateKey<T>,
    ) {
        todo!()
    }

    fn do_test_oaep_with_different_hashes_traits<
        T: UnsignedModularInt,
        D: Digest,
        MGD: Digest + FixedOutputReset,
    >(
        prk: &RsaPrivateKey<T>,
    ) {
        todo!()
    }

    #[test]
    #[ignore]
    fn test_decrypt_oaep_invalid_hash_traits() {
        todo!()
    }
}
