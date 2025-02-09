//! Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
//!
use digest::{Digest, DynDigest, FixedOutputReset};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroizing;

use super::mgf::{mgf1_xor, mgf1_xor_digest};
use crate::errors::{Error, Result};

mod label;
pub use label::Label;

/// Maximum label size (2^64 bits) for SHA-1 and SHA-256 hash functions.
///
/// In theory, other hash functions (e.g. SHA-512 and SHA-3) can process longer labels,
/// but such huge inputs are practically impossible on one machine, so we use this limit
/// for all hash functions.
const MAX_LABEL_LEN: u64 = 1 << 61;

// Maxiumum supported length of digests
const MAX_DIGEST_LEN: usize = 64;

#[inline]
fn encrypt_internal<'a, R: CryptoRngCore + ?Sized, MGF: FnMut(&mut [u8], &mut [u8])>(
    rng: &mut R,
    msg: &[u8],
    p_hash: &[u8],
    h_size: usize,
    k: usize,
    mut mgf: MGF,
    storage: &'a mut [u8],
) -> Result<&'a [u8]> {
    if msg.len() + 2 * h_size + 2 > k {
        return Err(Error::MessageTooLong);
    }
    let mut em = storage.get_mut(..k).ok_or(Error::OutputBufferTooSmall)?;

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h_size);
    rng.fill_bytes(seed);

    // Data block DB =  pHash || PS || 01 || M
    let db_len = k - h_size - 1;

    db[0..h_size].copy_from_slice(p_hash);
    db[db_len - msg.len() - 1] = 1;
    db[db_len - msg.len()..].copy_from_slice(msg);

    mgf(seed, db);

    Ok(em)
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub(crate) fn oaep_encrypt<'a, R: CryptoRngCore + ?Sized, D>(
    rng: &mut R,
    msg: &[u8],
    digest: &mut D,
    mgf_digest: &mut D,
    label: Option<Label>,
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    D: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    todo!()
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub(crate) fn oaep_encrypt_digest<
    'a,
    R: CryptoRngCore + ?Sized,
    D: Digest,
    MGD: Digest + FixedOutputReset,
>(
    rng: &mut R,
    msg: &[u8],
    label: Option<Label>,
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]> {
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    let p_hash = D::digest(label.as_bytes());

    encrypt_internal(
        rng,
        msg,
        &p_hash,
        h_size,
        k,
        |seed, db| {
            let mut mgf_digest = MGD::new();
            mgf1_xor_digest(db, &mut mgf_digest, seed);
            mgf1_xor_digest(seed, &mut mgf_digest, db);
    },
    storage,
)
}

///Decrypts OAEP padding.
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
pub(crate) fn oaep_decrypt<'a, D>(
    em: &mut [u8],
    digest: &mut D,
    mgf_digest: &mut D,
    label: Option<Label>,
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    D: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();
    todo!()
}

///Decrypts OAEP padding.
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
pub(crate) fn oaep_decrypt_digest<'a, D: Digest, MGD: Digest + FixedOutputReset>(
    em: &mut [u8],
    label: Option<Label>,
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]> {
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    let expected_p_hash = D::digest(label.as_bytes());

    let res = decrypt_inner(em, h_size, &expected_p_hash, k, |seed, db| {
        let mut mgf_digest = MGD::new();
        mgf1_xor_digest(seed, &mut mgf_digest, db);
        mgf1_xor_digest(db, &mut mgf_digest, seed);
    }, storage)?;
    if res.is_none().into() {
        return Err(Error::Decryption);
    }

    let (out, index) = res.unwrap();

    todo!()
}

/// Decrypts OAEP padding. It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured.
#[inline]
fn decrypt_inner<'a,MGF: FnMut(&mut [u8], &mut [u8])>(
    em: &mut [u8],
    h_size: usize,
    expected_p_hash: &[u8],
    k: usize,
    mut mgf: MGF,
    storage: &'a mut [u8],
) -> Result<CtOption<(&'a [u8], u32)>> {    
    if k < 11 {
        return Err(Error::Decryption);
    }

    if k < h_size * 2 + 2 {
        return Err(Error::Decryption);
    }

    let first_byte_is_zero = em[0].ct_eq(&0u8);

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h_size);

    mgf(seed, db);

    let hash_are_equal = db[0..h_size].ct_eq(expected_p_hash);

    // The remainder of the plaintext must be zero or more 0x00, followed
    // by 0x01, followed by the message.
    //   looking_for_index: 1 if we are still looking for the 0x01
    //   index: the offset of the first 0x01 byte
    //   zero_before_one: 1 if we saw a non-zero byte before the 1
    let mut looking_for_index = Choice::from(1u8);
    let mut index = 0u32;
    let mut nonzero_before_one = Choice::from(0u8);

    for (i, el) in db.iter().skip(h_size).enumerate() {
        let equals0 = el.ct_eq(&0u8);
        let equals1 = el.ct_eq(&1u8);
        index.conditional_assign(&(i as u32), looking_for_index & equals1);
        looking_for_index &= !equals1;
        nonzero_before_one |= looking_for_index & !equals0;
    }

    let valid = first_byte_is_zero & hash_are_equal & !nonzero_before_one & !looking_for_index;

    todo!()
}
