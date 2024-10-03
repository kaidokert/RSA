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

use digest::{Digest, DynDigest, FixedOutputReset};
use subtle::{Choice, ConstantTimeEq};

use super::mgf::{mgf1_xor, mgf1_xor_digest};
use crate::errors::{Error, Result};

#[cfg(feature = "std")]
use std::println;

// Maxiumum supported length of digests
// This gets temporarily stack-allocated
const MAX_DIGEST_LEN: usize = 64;

pub(crate) fn emsa_pss_encode(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
    hash: &mut dyn DynDigest,
) -> Result<()> {
    todo!()
}

pub(crate) fn emsa_pss_encode_digest<D>(m_hash: &[u8], em_bits: usize, salt: &[u8]) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    todo!()
}

fn emsa_pss_verify_pre<'a>(
    m_hash: &[u8],
    em: &'a mut [u8],
    em_bits: usize,
    s_len: usize,
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

    // 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    let em_len = em.len(); //(em_bits + 7) / 8;
    if em_len < h_len + s_len + 2 {
        return Err(Error::Verification);
    }

    // 4. If the rightmost octet of EM does not have hexadecimal value
    //    0xbc, output "inconsistent" and stop.
    #[cfg(feature = "std")]
    println!("em[last]: {:x?}", em[em.len() - 1]);
    if em[em.len() - 1] != 0xBC {
        return Err(Error::Verification);
    }

    // 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
    //    let H be the next hLen octets.
    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..h_len];

    #[cfg(feature = "std")]
    println!("db: {:x?}", db);
    #[cfg(feature = "std")]
    println!("h: {:x?}", h);
    #[cfg(feature = "std")]
    println!("em_len: {} em_bits {}", em_len, em_bits);

    // 6. If the leftmost 8 * em_len - em_bits bits of the leftmost octet in
    //    maskedDB are not all equal to zero, output "inconsistent" and
    //    stop.
    if db[0]
        & (0xFF_u8
            .checked_shl(8 - (8 * em_len - em_bits) as u32)
            .unwrap_or(0))
        != 0
    {
        #[cfg(feature = "std")]
        println!("Verification error");
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
    let valid: Choice = zeroes
        .iter()
        .fold(Choice::from(1u8), |a, e| a & e.ct_eq(&0x00));

    valid & rest[0].ct_eq(&0x01)
}

pub(crate) fn emsa_pss_verify(
    m_hash: &[u8],
    em: &mut [u8],
    s_len: usize,
    hash: &mut dyn DynDigest,
    key_bits: usize,
) -> Result<()> {
    let em_bits = key_bits - 1;
    let em_len = (em_bits + 7) / 8;
    let key_len = (key_bits + 7) / 8;
    let h_len = hash.output_size();

    let em = &mut em[key_len - em_len..];

    let (db, h) = emsa_pss_verify_pre(m_hash, em, em_bits, s_len, h_len)?;

    // 7. Let dbMask = MGF(H, em_len - h_len - 1)
    //
    // 8. Let DB = maskedDB \xor dbMask
    mgf1_xor(db, hash, &*h);

    // 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    db[0] &= 0xFF >> /*uint*/(8 * em_len - em_bits);

    let salt_valid = emsa_pss_verify_salt(db, em_len, s_len, h_len);

    // 11. Let salt be the last s_len octets of DB.
    let salt = &db[db.len() - s_len..];

    // 12. Let
    //          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    //     M' is an octet string of length 8 + hLen + sLen with eight
    //     initial zero octets.
    //
    // 13. Let H' = Hash(M'), an octet string of length hLen.
    let prefix = [0u8; 8];

    hash.update(&prefix[..]);
    hash.update(m_hash);
    hash.update(salt);
    let mut digest_storage = [0u8; MAX_DIGEST_LEN];
    hash.finalize_into_reset(&mut digest_storage)
        .or(Err(Error::DigestBufferTooSmall))?;
    let h0 = &digest_storage[..h_len];

    // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    if (salt_valid & h0.ct_eq(h)).into() {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

pub(crate) fn emsa_pss_verify_digest<D>(
    m_hash: &[u8],
    em: &mut [u8],
    s_len: usize,
    key_bits: usize,
) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    let em_bits = key_bits - 1;
    let em_len = (em_bits + 7) / 8;
    let key_len = (key_bits + 7) / 8;
    let h_len = <D as Digest>::output_size();

    let em = &mut em[key_len - em_len..];

    #[cfg(feature = "std")]
    {
        println!("len em: {}", em.len());
        println!("em: {:x?}", em);
        println!("em[0]: {}", em[0]);
        println!("em[1]: {}", em[1]);
        println!("em[last]: {:x?}", em[em.len() - 1]);
    }

    let (db, h) = emsa_pss_verify_pre(m_hash, em, em_bits, s_len, h_len)?;

    let mut hash = D::new();

    // 7. Let dbMask = MGF(H, em_len - h_len - 1)
    //
    // 8. Let DB = maskedDB \xor dbMask
    mgf1_xor_digest::<D>(db, &mut hash, &*h);

    // 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    db[0] &= 0xFF >> /*uint*/(8 * em_len - em_bits);

    let salt_valid = emsa_pss_verify_salt(db, em_len, s_len, h_len);

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
    if (salt_valid & h0.ct_eq(h)).into() {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}
