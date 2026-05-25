//! Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
//!
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use ctutils::{Choice, CtAssign, CtEq, CtOption};
use digest::{Digest, FixedOutputReset};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use super::mgf::{mgf1_xor, mgf1_xor_digest};
use crate::errors::{Error, Result};

/// Maximum label size (2^64 bits) for SHA-1 and SHA-256 hash functions.
///
/// In theory, other hash functions (e.g. SHA-512 and SHA-3) can process longer labels,
/// but such huge inputs are practically impossible on one machine, so we use this limit
/// for all hash functions.
const MAX_LABEL_LEN: u64 = 1 << 61;

#[inline]
fn encrypt_internal_into<R: TryCryptoRng + ?Sized, MGF: FnMut(&mut [u8], &mut [u8])>(
    rng: &mut R,
    msg: &[u8],
    p_hash: &[u8],
    h_size: usize,
    k: usize,
    mut mgf: MGF,
    em: &mut [u8],
) -> Result<()> {
    if msg.len() + 2 * h_size + 2 > k {
        return Err(Error::MessageTooLong);
    }
    let em = em.get_mut(..k).ok_or(Error::OutputBufferTooSmall)?;
    em.fill(0);

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h_size);
    rng.try_fill_bytes(seed).map_err(|_| Error::Rng)?;

    // Data block DB =  pHash || PS || 01 || M
    let db_len = k - h_size - 1;

    db[0..h_size].copy_from_slice(p_hash);
    db[db_len - msg.len() - 1] = 1;
    db[db_len - msg.len()..].copy_from_slice(msg);

    mgf(seed, db);

    Ok(())
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn oaep_encrypt<R, D, MGD>(
    rng: &mut R,
    msg: &[u8],
    digest: &mut D,
    mgf_digest: &mut MGD,
    label: Option<Box<[u8]>>,
    k: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    R: TryCryptoRng + ?Sized,
    D: Digest + FixedOutputReset,
    MGD: Digest + FixedOutputReset,
{
    let mut em = Zeroizing::new(vec![0u8; k]);
    oaep_encrypt_into(rng, msg, digest, mgf_digest, label.as_deref(), k, &mut em)?;
    Ok(em)
}

#[inline]
pub(crate) fn oaep_encrypt_into<'a, R, D, MGD>(
    rng: &mut R,
    msg: &[u8],
    digest: &mut D,
    mgf_digest: &mut MGD,
    label: Option<&[u8]>,
    k: usize,
    em: &'a mut [u8],
) -> Result<&'a [u8]>
where
    R: TryCryptoRng + ?Sized,
    D: Digest + FixedOutputReset,
    MGD: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    Digest::update(digest, label);
    let p_hash = digest.finalize_reset();

    let mgf = |seed: &mut [u8], db: &mut [u8]| {
        mgf1_xor(db, mgf_digest, seed);
        mgf1_xor(seed, mgf_digest, db);
    };
    encrypt_internal_into(rng, msg, &p_hash, h_size, k, mgf, em)?;
    Ok(&em[..k])
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[cfg(feature = "alloc")]
#[inline]
#[allow(dead_code)]
pub(crate) fn oaep_encrypt_digest<R, D, MGD>(
    rng: &mut R,
    msg: &[u8],
    label: Option<Box<[u8]>>,
    k: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    R: TryCryptoRng + ?Sized,
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    let mut em = Zeroizing::new(vec![0u8; k]);
    oaep_encrypt_digest_into::<R, D, MGD>(rng, msg, label.as_deref(), k, &mut em)?;
    Ok(em)
}

#[inline]
pub(crate) fn oaep_encrypt_digest_into<'a, R, D, MGD>(
    rng: &mut R,
    msg: &[u8],
    label: Option<&[u8]>,
    k: usize,
    em: &'a mut [u8],
) -> Result<&'a [u8]>
where
    R: TryCryptoRng + ?Sized,
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    let p_hash = D::digest(label);

    let mgf = |seed: &mut [u8], db: &mut [u8]| {
        let mut mgf_digest = MGD::new();
        mgf1_xor_digest(db, &mut mgf_digest, seed);
        mgf1_xor_digest(seed, &mut mgf_digest, db);
    };
    encrypt_internal_into(rng, msg, &p_hash, h_size, k, mgf, em)?;
    Ok(&em[..k])
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
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn oaep_decrypt<D, MGD>(
    em: &mut [u8],
    digest: &mut D,
    mgf_digest: &mut MGD,
    label: Option<Box<[u8]>>,
    k: usize,
) -> Result<Vec<u8>>
where
    D: Digest + FixedOutputReset,
    MGD: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::Decryption);
    }

    Digest::update(digest, &label);

    let expected_p_hash = digest.finalize_reset();

    let res = decrypt_inner(em, h_size, &expected_p_hash, k, |seed, db| {
        mgf1_xor(seed, mgf_digest, db);
        mgf1_xor(db, mgf_digest, seed);
    })?;
    if res.is_none().into() {
        return Err(Error::Decryption);
    }

    let index = res.unwrap();

    Ok(em[index as usize..].to_vec())
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
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn oaep_decrypt_digest<D, MGD>(
    em: &mut [u8],
    label: Option<Box<[u8]>>,
    k: usize,
) -> Result<Vec<u8>>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    let h_size = <D as Digest>::output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    let expected_p_hash = D::digest(&label);

    let res = decrypt_inner(em, h_size, &expected_p_hash, k, |seed, db| {
        let mut mgf_digest = MGD::new();
        mgf1_xor_digest(seed, &mut mgf_digest, db);
        mgf1_xor_digest(db, &mut mgf_digest, seed);
    })?;
    if res.is_none().into() {
        return Err(Error::Decryption);
    }

    let index = res.unwrap();

    Ok(em[index as usize..].to_vec())
}

/// Decrypts OAEP padding. It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured.
#[cfg(feature = "alloc")]
#[inline]
fn decrypt_inner<MGF: FnMut(&mut [u8], &mut [u8])>(
    em: &mut [u8],
    h_size: usize,
    expected_p_hash: &[u8],
    k: usize,
    mut mgf: MGF,
) -> Result<CtOption<u32>> {
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
    let mut looking_for_index = Choice::TRUE;
    let mut index = 0u32;
    let mut nonzero_before_one = Choice::FALSE;

    for (i, el) in db.iter().skip(h_size).enumerate() {
        let equals0 = el.ct_eq(&0u8);
        let equals1 = el.ct_eq(&1u8);
        index.ct_assign(&(i as u32), looking_for_index & equals1);
        looking_for_index &= !equals1;
        nonzero_before_one |= looking_for_index & !equals0;
    }

    let valid = first_byte_is_zero & hash_are_equal & !nonzero_before_one & !looking_for_index;

    Ok(CtOption::new(index + 2 + (h_size * 2) as u32, valid))
}
