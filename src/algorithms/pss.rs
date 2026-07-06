//! Support for the [Probabilistic Signature Scheme] (PSS) a.k.a. RSASSA-PSS.
//!
//! Designed by Mihir Bellare and Phillip Rogaway. Specified in [RFC8017 § 8.1].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pss-signatures).
//!
//! [Probabilistic Signature Scheme]: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
//! [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use ctutils::{Choice, CtEq, CtSelect};
use digest::{Digest, FixedOutputReset};

use super::mgf::{mgf1_xor, mgf1_xor_digest};
use crate::errors::{Error, Result};
#[cfg(any(feature = "private-key", feature = "wip-private-key"))]
use crate::traits::{
    modular::{ModulusParams, Pow, PowBoundedExp},
    UnsignedModularInt,
};

#[cfg(feature = "alloc")]
pub(crate) fn emsa_pss_encode<D>(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
    hash: &mut D,
) -> Result<Vec<u8>>
where
    D: Digest + FixedOutputReset,
{
    let em_len = em_bits.div_ceil(8);
    let mut em = vec![0; em_len];
    emsa_pss_encode_into(m_hash, em_bits, salt, hash, &mut em)?;
    Ok(em)
}

/// EMSA-PSS encode, RFC 8017 § 9.1.1 — slice-output variant.
///
/// Writes exactly `em_len = em_bits.div_ceil(8)` bytes into the head of
/// `storage`. `storage.len()` must be at least `em_len`; on success, the
/// returned slice is `&storage[..em_len]`.
#[inline]
pub fn emsa_pss_encode_into<'a, D>(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
    hash: &mut D,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    D: Digest + FixedOutputReset,
{
    // See [1], section 9.1.1
    let h_len = <D as Digest>::output_size();
    let s_len = salt.len();
    let em_len = em_bits.div_ceil(8);

    // 1. If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "message too
    //     long" and stop.
    //
    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    if m_hash.len() != h_len {
        return Err(Error::InputNotHashed);
    }

    // 3. If em_len < h_len + s_len + 2, output "encoding error" and stop.
    if em_len < h_len + s_len + 2 {
        // TODO: Key size too small
        return Err(Error::Internal);
    }

    let em = storage
        .get_mut(..em_len)
        .ok_or(Error::OutputBufferTooSmall)?;
    em.fill(0);

    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..(em_len - 1) - db.len()];

    // 4. Generate a random octet string salt of length s_len; if s_len = 0,
    //     then salt is the empty string.
    //
    // 5.  Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || m_hash || salt;
    //
    //     M' is an octet string of length 8 + h_len + s_len with eight
    //     initial zero octets.
    //
    // 6.  Let H = Hash(M'), an octet string of length h_len.
    let prefix = [0u8; 8];

    Digest::update(hash, prefix);
    Digest::update(hash, m_hash);
    Digest::update(hash, salt);

    let hashed = hash.finalize_reset();
    h.copy_from_slice(&hashed);

    // 7.  Generate an octet string PS consisting of em_len - s_len - h_len - 2
    //     zero octets. The length of PS may be 0.
    //
    // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
    //     emLen - hLen - 1.
    db[em_len - s_len - h_len - 2] = 0x01;
    db[em_len - s_len - h_len - 1..].copy_from_slice(salt);

    // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
    //
    // 10. Let maskedDB = DB \xor dbMask.
    mgf1_xor(db, hash, h);

    // 11. Set the leftmost 8 * em_len - em_bits bits of the leftmost octet in
    //     maskedDB to zero.
    db[0] &= 0xFF >> (8 * em_len - em_bits);

    // 12. Let EM = maskedDB || H || 0xbc.
    em[em_len - 1] = 0xBC;

    Ok(em)
}

#[cfg(feature = "alloc")]
pub(crate) fn emsa_pss_encode_digest<D>(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
) -> Result<Vec<u8>>
where
    D: Digest + FixedOutputReset,
{
    // See [1], section 9.1.1
    let h_len = <D as Digest>::output_size();
    let s_len = salt.len();
    let em_len = em_bits.div_ceil(8);

    // 1. If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "message too
    //     long" and stop.
    //
    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    if m_hash.len() != h_len {
        return Err(Error::InputNotHashed);
    }

    // 3. If em_len < h_len + s_len + 2, output "encoding error" and stop.
    if em_len < h_len + s_len + 2 {
        // TODO: Key size too small
        return Err(Error::Internal);
    }

    let mut em = vec![0; em_len];

    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..(em_len - 1) - db.len()];

    // 4. Generate a random octet string salt of length s_len; if s_len = 0,
    //     then salt is the empty string.
    //
    // 5.  Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || m_hash || salt;
    //
    //     M' is an octet string of length 8 + h_len + s_len with eight
    //     initial zero octets.
    //
    // 6.  Let H = Hash(M'), an octet string of length h_len.
    let prefix = [0u8; 8];

    let mut hash = D::new();

    Digest::update(&mut hash, prefix);
    Digest::update(&mut hash, m_hash);
    Digest::update(&mut hash, salt);

    let hashed = hash.finalize_reset();
    h.copy_from_slice(&hashed);

    // 7.  Generate an octet string PS consisting of em_len - s_len - h_len - 2
    //     zero octets. The length of PS may be 0.
    //
    // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
    //     emLen - hLen - 1.
    db[em_len - s_len - h_len - 2] = 0x01;
    db[em_len - s_len - h_len - 1..].copy_from_slice(salt);

    // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
    //
    // 10. Let maskedDB = DB \xor dbMask.
    mgf1_xor_digest(db, &mut hash, h);

    // 11. Set the leftmost 8 * em_len - em_bits bits of the leftmost octet in
    //     maskedDB to zero.
    db[0] &= 0xFF >> (8 * em_len - em_bits);

    // 12. Let EM = maskedDB || H || 0xbc.
    em[em_len - 1] = 0xBC;

    Ok(em)
}

/// ⚠️ RSASSA-PSS sign — heapless-compatible, generic over the integer backend.
///
/// EMSA-PSS-encodes `(m_hash, salt)` (`em_bits = key_bits - 1`, RFC 8017
/// § 8.1.1), computes `s = EM^d mod n` via
/// [`rsa_private_op_and_check`](crate::algorithms::rsa::rsa_private_op_and_check)
/// (verify-after-sign on every backend), and writes `s` left-padded to `k`
/// bytes. `k` is the modulus byte length; `sig_storage`/`em_storage` are
/// length-checked up front.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// The raw PSS sign primitive — the caller hashes the message and generates
/// the random `salt`.
///
// Consumer (the heapless `pss::SigningKey<D>` wrapper) lands in a later PR.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)] // Composing four byte/integer steps; splitting helps nothing.
#[cfg(any(feature = "private-key", feature = "wip-private-key"))]
pub fn sign_into<'sig, T, M, D>(
    n_params: &M,
    d: &T,
    e: &T,
    m_hash: &[u8],
    salt: &[u8],
    k: usize,
    hash: &mut D,
    em_storage: &mut [u8],
    sig_storage: &'sig mut [u8],
) -> Result<&'sig [u8]>
where
    T: UnsignedModularInt,
    T::Bytes: zeroize::Zeroize,
    M: ModulusParams<Modulus = T> + crate::traits::modular::CtModulusParams,
    M::MontgomeryForm: Pow<M> + PowBoundedExp<M>,
    D: Digest + FixedOutputReset,
{
    // `k` = modulus byte length (matches `PublicKeyParts::size()`). Use the
    // actual bit-length, not the container width, and `div_ceil` so a
    // non-multiple-of-8 modulus still round-trips; `em_bits` needs it too.
    let key_bits = n_params.modulus().as_ref().bits() as usize;
    // Guard against degenerate moduli — `em_bits = key_bits - 1` would
    // otherwise underflow and surface as `OutputBufferTooSmall`.
    if key_bits < 2 {
        return Err(Error::InvalidArguments);
    }
    if k != key_bits.div_ceil(8) {
        return Err(Error::InvalidArguments);
    }
    if sig_storage.len() < k {
        return Err(Error::OutputBufferTooSmall);
    }
    // RFC 8017 § 8.1.1: em_bits ≡ modulus_bits − 1.
    let em_bits = key_bits - 1;
    if em_storage.len() < em_bits.div_ceil(8) {
        return Err(Error::OutputBufferTooSmall);
    }
    let em_slice = emsa_pss_encode_into(m_hash, em_bits, salt, hash, em_storage)?;
    let em = T::try_from_be_bytes_vartime(em_slice)?;
    let s = crate::algorithms::rsa::rsa_private_op_and_check(&em, d, e, n_params)?;
    crate::algorithms::pad::uint_to_zeroizing_be_pad_into(s, k, sig_storage)
}

fn emsa_pss_verify_pre<'a>(
    m_hash: &[u8],
    em: &'a mut [u8],
    em_bits: usize,
    s_len: Option<usize>,
    h_len: usize,
) -> Result<(&'a mut [u8], &'a mut [u8])> {
    // 1. If the length of M is greater than the input limitation for the
    //    hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
    //    and stop.
    //
    // 2. Let mHash = Hash(M), an octet string of length hLen
    if m_hash.len() != h_len {
        return Err(Error::Verification);
    }

    let em_len = em.len(); //(em_bits + 7) / 8;
    if let Some(s_len) = s_len {
        // 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
        if em_len < h_len + s_len + 2 {
            return Err(Error::Verification);
        }
    }

    // 4. If the rightmost octet of EM does not have hexadecimal value
    //    0xbc, output "inconsistent" and stop.
    if em[em.len() - 1] != 0xBC {
        return Err(Error::Verification);
    }

    // 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
    //    let H be the next hLen octets.
    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..h_len];

    // 6. If the leftmost 8 * em_len - em_bits bits of the leftmost octet in
    //    maskedDB are not all equal to zero, output "inconsistent" and
    //    stop.
    if db[0]
        & (0xFF_u8
            .checked_shl(8 - (8 * em_len - em_bits) as u32)
            .unwrap_or(0))
        != 0
    {
        return Err(Error::Verification);
    }

    Ok((db, h))
}

fn emsa_pss_verify_salt(db: &[u8], em_len: usize, s_len: usize, h_len: usize) -> Choice {
    // 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
    //     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
    //     position is "position 1") does not have hexadecimal value 0x01,
    //     output "inconsistent" and stop.
    let (zeroes, rest) = db.split_at(em_len - h_len - s_len - 2);
    let valid: Choice = zeroes.iter().fold(Choice::TRUE, |a, e| a & e.ct_eq(&0x00));

    valid & rest[0].ct_eq(&0x01)
}

/// Detect salt length by scanning DB for the 0x01 separator byte.
/// Returns (s_len, valid) where s_len is 0 on failure.
fn emsa_pss_get_salt_len(db: &[u8], em_len: usize, h_len: usize) -> (usize, Choice) {
    let em_len = em_len as u32;
    let h_len = h_len as u32;
    let max_scan_len = em_len - h_len - 2;

    let mut separator_pos = 0u32;
    let mut found_separator = Choice::FALSE;
    let mut padding_valid = Choice::TRUE;

    // Single forward scan to find separator and validate padding
    for i in 0..=max_scan_len {
        let byte_val = db[i as usize];
        let is_zero = byte_val.ct_eq(&0x00);
        let is_separator = byte_val.ct_eq(&0x01);
        let is_invalid = !(is_zero | is_separator);

        // Update separator position if we found one and haven't found one before
        let should_update_pos = is_separator & !found_separator;
        separator_pos = u32::ct_select(&separator_pos, &i, should_update_pos);
        found_separator = Choice::ct_select(&found_separator, &Choice::TRUE, should_update_pos);

        // Padding is invalid if we see a non-zero, non-separator byte before finding separator
        let corrupts_padding = is_invalid & !found_separator;
        padding_valid &= !corrupts_padding;
    }

    let salt_len = max_scan_len.wrapping_sub(separator_pos);
    let final_valid = found_separator & padding_valid;

    // Return 0 length on failure
    let result_len = u32::ct_select(&0u32, &salt_len, final_valid);

    (result_len as usize, final_valid)
}

pub(crate) fn emsa_pss_verify<D>(
    m_hash: &[u8],
    em: &mut [u8],
    s_len: Option<usize>,
    hash: &mut D,
    key_bits: usize,
) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    let em_bits = key_bits - 1;
    let em_len = em_bits.div_ceil(8);
    let key_len = key_bits.div_ceil(8);
    let h_len = <D as Digest>::output_size();

    let em = &mut em[key_len - em_len..];

    let (db, h) = emsa_pss_verify_pre(m_hash, em, em_bits, s_len, h_len)?;

    // 7. Let dbMask = MGF(H, em_len - h_len - 1)
    //
    // 8. Let DB = maskedDB \xor dbMask
    mgf1_xor(db, hash, &*h);

    // 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    db[0] &= 0xFF >> /*uint*/(8 * em_len - em_bits);

    let (s_len, salt_valid) = match s_len {
        Some(s_len) => (s_len, emsa_pss_verify_salt(db, em_len, s_len, h_len)),
        None => emsa_pss_get_salt_len(db, em_len, h_len),
    };

    // 11. Let salt be the last s_len octets of DB.
    let salt = &db[db.len() - s_len..];

    // 12. Let
    //          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    //     M' is an octet string of length 8 + hLen + sLen with eight
    //     initial zero octets.
    //
    // 13. Let H' = Hash(M'), an octet string of length hLen.
    let prefix = [0u8; 8];

    Digest::update(hash, &prefix[..]);
    Digest::update(hash, m_hash);
    Digest::update(hash, salt);
    let h0 = hash.finalize_reset();

    // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    if (salt_valid & h0.as_slice().ct_eq(h)).into() {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

pub(crate) fn emsa_pss_verify_digest<D>(
    m_hash: &[u8],
    em: &mut [u8],
    s_len: Option<usize>,
    key_bits: usize,
) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    let em_bits = key_bits - 1;
    let em_len = em_bits.div_ceil(8);
    let key_len = key_bits.div_ceil(8);
    let h_len = <D as Digest>::output_size();

    let em = &mut em[key_len - em_len..];

    let (db, h) = emsa_pss_verify_pre(m_hash, em, em_bits, s_len, h_len)?;

    let mut hash = D::new();

    // 7. Let dbMask = MGF(H, em_len - h_len - 1)
    //
    // 8. Let DB = maskedDB \xor dbMask
    mgf1_xor_digest::<D>(db, &mut hash, &*h);

    // 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    db[0] &= 0xFF >> /*uint*/(8 * em_len - em_bits);

    let (s_len, salt_valid) = match s_len {
        Some(s_len) => (s_len, emsa_pss_verify_salt(db, em_len, s_len, h_len)),
        None => emsa_pss_get_salt_len(db, em_len, h_len),
    };

    // 11. Let salt be the last s_len octets of DB.
    let salt = &db[db.len() - s_len..];

    // 12. Let
    //          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    //     M' is an octet string of length 8 + hLen + sLen with eight
    //     initial zero octets.
    //
    // 13. Let H' = Hash(M'), an octet string of length hLen.
    let prefix = [0u8; 8];

    Digest::update(&mut hash, &prefix[..]);
    Digest::update(&mut hash, m_hash);
    Digest::update(&mut hash, salt);
    let h0 = hash.finalize_reset();

    // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    if (salt_valid & h0.as_slice().ct_eq(h)).into() {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}
