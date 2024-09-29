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
    todo!()
}
