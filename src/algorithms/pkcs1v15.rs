//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use const_oid::AssociatedOid;
use ctutils::{Choice, CtAssign, CtEq, CtSelect};
use digest::Digest;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Fills the provided slice with random values, which are guaranteed
/// to not be zero.
#[inline]
fn non_zero_random_bytes<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    data: &mut [u8],
) -> core::result::Result<(), R::Error> {
    rng.try_fill_bytes(data)?;

    for el in data {
        if *el == 0u8 {
            // TODO: break after a certain amount of time
            while *el == 0u8 {
                rng.try_fill_bytes(core::slice::from_mut(el))?;
            }
        }
    }

    Ok(())
}

/// Applied the padding scheme from PKCS#1 v1.5 for encryption.  The message must be no longer than
/// the length of the public modulus minus 11 bytes.
#[cfg(feature = "alloc")]
#[allow(dead_code)] // used by in-module tests; kept as the Vec-returning convenience wrapper
pub(crate) fn pkcs1v15_encrypt_pad<R>(
    rng: &mut R,
    msg: &[u8],
    k: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    R: TryCryptoRng + ?Sized,
{
    let mut em = Zeroizing::new(vec![0u8; k]);
    pkcs1v15_encrypt_pad_into(rng, msg, k, &mut em)?;
    Ok(em)
}

pub fn pkcs1v15_encrypt_pad_into<'a, R>(
    rng: &mut R,
    msg: &[u8],
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    R: TryCryptoRng + ?Sized,
{
    if msg.len() + 11 > k {
        return Err(Error::MessageTooLong);
    }
    // EM = 0x00 || 0x02 || PS || 0x00 || M
    let em = storage.get_mut(..k).ok_or(Error::OutputBufferTooSmall)?;
    em[0] = 0;
    em[1] = 2;
    non_zero_random_bytes(rng, &mut em[2..k - msg.len() - 1]).map_err(|_: R::Error| Error::Rng)?;
    em[k - msg.len() - 1] = 0;
    em[k - msg.len()..].copy_from_slice(msg);
    Ok(em)
}

/// Removes the encryption padding scheme from PKCS#1 v1.5.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key. See
/// `decrypt_session_key` for a way of solving this problem.
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn pkcs1v15_encrypt_unpad(em: Vec<u8>, k: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; k];
    let out = pkcs1v15_encrypt_unpad_into(&em, k, &mut out)?;
    Ok(out.to_vec())
}

#[inline]
pub fn pkcs1v15_encrypt_unpad_into<'a>(
    em: &[u8],
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]> {
    let (valid, index) = decrypt_inner(em, k)?;
    if valid == 0 {
        return Err(Error::Decryption);
    }

    let out = storage.get_mut(..k).ok_or(Error::OutputBufferTooSmall)?;
    out.copy_from_slice(em);
    Ok(&out[index as usize..])
}

/// Removes the PKCS1v15 padding It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured. In either case, the plaintext is
/// returned in em so that it may be read independently of whether it was valid
/// in order to maintain constant memory access patterns. If the plaintext was
/// valid then index contains the index of the original message in em.
#[inline]
fn decrypt_inner(em: &[u8], k: usize) -> Result<(u8, u32)> {
    if k < 11 {
        return Err(Error::Decryption);
    }

    let first_byte_is_zero = em[0].ct_eq(&0u8);
    let second_byte_is_two = em[1].ct_eq(&2u8);

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   looking_for_index: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    let mut looking_for_index = Choice::TRUE;
    let mut index = 0u32;

    for (i, el) in em.iter().enumerate().skip(2) {
        let equals0 = el.ct_eq(&0u8);
        index.ct_assign(&(i as u32), looking_for_index & equals0);
        looking_for_index &= !equals0;
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em.
    // TODO: WARNING: THIS MUST BE CONSTANT TIME CHECK:
    // Ref: https://github.com/dalek-cryptography/subtle/issues/20
    // This is currently copy & paste from the constant time impl in
    // go, but very likely not sufficient.
    let valid_ps = Choice::from_u8_lsb((((2i32 + 8i32 - index as i32 - 1i32) >> 31) & 1) as u8);
    let valid = first_byte_is_zero & second_byte_is_two & !looking_for_index & valid_ps;
    index = u32::ct_select(&0, &(index + 1), valid);

    Ok((valid.to_u8(), index))
}

#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn pkcs1v15_sign_pad(prefix: &[u8], hashed: &[u8], k: usize) -> Result<Vec<u8>> {
    let mut em = vec![0xff; k];
    pkcs1v15_sign_pad_into(prefix, hashed, k, &mut em)?;
    Ok(em)
}

#[inline]
pub fn pkcs1v15_sign_pad_into<'a>(
    prefix: &[u8],
    hashed: &[u8],
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::MessageTooLong);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let em = storage.get_mut(..k).ok_or(Error::OutputBufferTooSmall)?;
    em[0] = 0;
    em[1] = 1;
    em[2..k - t_len - 1].fill(0xff);
    em[k - t_len - 1] = 0;
    em[k - t_len..k - hash_len].copy_from_slice(prefix);
    em[k - hash_len..k].copy_from_slice(hashed);

    Ok(em)
}

#[inline]
pub(crate) fn pkcs1v15_sign_unpad(prefix: &[u8], hashed: &[u8], em: &[u8], k: usize) -> Result<()> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::Verification);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut ok = em[0].ct_eq(&0u8);
    ok &= em[1].ct_eq(&1u8);
    ok &= em[k - hash_len..k].ct_eq(hashed);
    ok &= em[k - t_len..k - hash_len].ct_eq(prefix);
    ok &= em[k - t_len - 1].ct_eq(&0u8);

    for el in em.iter().skip(2).take(k - t_len - 3) {
        ok &= el.ct_eq(&0xff)
    }

    // TODO(tarcieri): avoid branching here by e.g. using a pseudorandom rejection symbol
    if !ok.to_bool() {
        return Err(Error::Verification);
    }

    Ok(())
}

/// prefix = 0x30 <oid_len + 8 + digest_len> 0x30 <oid_len + 4> 0x06 <oid_len> oid 0x05 0x00 0x04 <digest_len>
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn pkcs1v15_generate_prefix<D>() -> Vec<u8>
where
    D: Digest + AssociatedOid,
{
    let oid = D::OID.as_bytes();
    let mut v = vec![0u8; oid.len() + 10];
    let out = pkcs1v15_generate_prefix_into::<D>(&mut v)
        .expect("pkcs1v15 prefix buffer should fit exact size");
    out.to_vec()
}

#[inline]
pub fn pkcs1v15_generate_prefix_into<D>(storage: &mut [u8]) -> Result<&[u8]>
where
    D: Digest + AssociatedOid,
{
    let oid = D::OID.as_bytes();
    let oid_len = oid.len() as u8;
    let digest_len = <D as Digest>::output_size() as u8;
    let out = storage
        .get_mut(..oid.len() + 10)
        .ok_or(Error::OutputBufferTooSmall)?;
    out[..6].copy_from_slice(&[
        0x30,
        oid_len + 8 + digest_len,
        0x30,
        oid_len + 4,
        0x6,
        oid_len,
    ]);
    out[6..6 + oid.len()].copy_from_slice(oid);
    out[6 + oid.len()..oid.len() + 10].copy_from_slice(&[0x05, 0x00, 0x04, digest_len]);
    Ok(&out[..oid.len() + 10])
}

#[cfg(test)]
#[cfg(feature = "private-key")]
mod tests {
    use super::*;
    use rand::rngs::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_non_zero_bytes() {
        for _ in 0..10 {
            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let mut b = vec![0u8; 512];
            non_zero_random_bytes(&mut rng, &mut b).unwrap();
            for el in &b {
                assert_ne!(*el, 0u8);
            }
        }
    }

    #[test]
    fn test_encrypt_tiny_no_crash() {
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let k = 8;
        let message = vec![1u8; 4];
        let res = pkcs1v15_encrypt_pad(&mut rng, &message, k);
        assert_eq!(res, Err(Error::MessageTooLong));
    }
}
