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
    if em[em.len() - 1] != 0xBC {
        return Err(Error::Verification);
    }

    // 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
    //    let H be the next hLen octets.
    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..h_len];

    todo!()
}

fn emsa_pss_verify_salt(db: &[u8], em_len: usize, s_len: usize, h_len: usize) -> Choice {
    todo!()
}

pub(crate) fn emsa_pss_verify(
    m_hash: &[u8],
    em: &mut [u8],
    s_len: usize,
    hash: &mut dyn DynDigest,
    key_bits: usize,
) -> Result<()> {
    todo!()
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

    todo!()
}
