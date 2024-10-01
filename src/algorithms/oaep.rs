//! Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
//!
use digest::{Digest, DynDigest, FixedOutputReset};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroizing;

use super::mgf::{mgf1_xor, mgf1_xor_digest};
use crate::errors::{Error, Result};

use heapless::String;

/// Maximum label size (2^64 bits) for SHA-1 and SHA-256 hash functions.
///
/// In theory, other hash functions (e.g. SHA-512 and SHA-3) can process longer labels,
/// but such huge inputs are practically impossible on one machine, so we use this limit
/// for all hash functions.
const MAX_LABEL_LEN: u64 = 1 << 61;

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

    //let mut em = Zeroizing::new(vec![0u8; k]);
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
pub(crate) fn oaep_encrypt<'a, R: CryptoRngCore + ?Sized>(
    rng: &mut R,
    msg: &[u8],
    digest: &mut dyn DynDigest,
    mgf_digest: &mut dyn DynDigest,
    label: Option<String<128>>,
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]> {
    let h_size = digest.output_size();

    let label = label.unwrap_or_default();
    if label.len() as u64 >= MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    digest.update(label.as_bytes());
    let p_hash = digest.finalize_reset();

    encrypt_internal(
        rng,
        msg,
        &p_hash,
        h_size,
        k,
        |seed, db| {
            mgf1_xor(db, mgf_digest, seed);
            mgf1_xor(seed, mgf_digest, db);
        },
        storage,
    )
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
    label: Option<String<128>>,
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
