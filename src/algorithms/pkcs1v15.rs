//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

use const_oid::AssociatedOid;
use digest::Digest;
use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::Prefix;

use crate::errors::{Error, Result};
#[cfg(feature = "std")]
use std::println;

/// Fills the provided slice with random values, which are guaranteed
/// to not be zero.
#[inline]
fn non_zero_random_bytes<R: CryptoRngCore + ?Sized>(rng: &mut R, data: &mut [u8]) {
    rng.fill_bytes(data);

    for el in data {
        if *el == 0u8 {
            // TODO: break after a certain amount of time
            while *el == 0u8 {
                rng.fill_bytes(core::slice::from_mut(el));
            }
        }
    }
}

/// Applied the padding scheme from PKCS#1 v1.5 for encryption.  The message must be no longer than
/// the length of the public modulus minus 11 bytes.
pub(crate) fn pkcs1v15_encrypt_pad<'a, R>(
    rng: &mut R,
    msg: &[u8],
    k: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]>
where
    R: CryptoRngCore + ?Sized,
{
    if msg.len() > k - 11 {
        return Err(Error::MessageTooLong);
    }
    // TODO: em should be a Zeroizing type
    // EM = 0x00 || 0x02 || PS || 0x00 || M
    let em = storage.get_mut(..k).ok_or(Error::OutputBufferTooSmall)?;
    em[0] = 0;
    em[1] = 2;
    non_zero_random_bytes(rng, &mut em[2..k - msg.len() - 1]);
    em[k - msg.len() - 1] = 0;
    em[k - msg.len()..].copy_from_slice(msg);
    Ok(em)
}

#[inline]
pub(crate) fn pkcs1v15_sign_unpad(prefix: &[u8], hashed: &[u8], em: &[u8], k: usize) -> Result<()> {
    let hash_len = hashed.len();
    #[cfg(feature = "std")]
    {
        println!("len em: {}", em.len());
        println!("em: {:x?}", em);
        println!("em[0]: {}", em[0]);
        println!("em[1]: {}", em[1]);
    }
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::Verification);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut ok = em[0].ct_eq(&0u8);
    ok &= em[1].ct_eq(&1u8);
    #[cfg(feature = "std")]
    println!("hash_block: {:x?} {:?}", &em[k - hash_len..k], ok);
    ok &= em[k - hash_len..k].ct_eq(hashed);
    #[cfg(feature = "std")]
    println!(
        "prefix_block: {:x?} prefix={:x?} {:?}",
        &em[k - t_len..k - hash_len],
        prefix,
        ok
    );
    ok &= em[k - t_len..k - hash_len].ct_eq(prefix);

    #[cfg(feature = "std")]
    println!("required zero: {:x?} {:?}", &em[k - t_len - 1], ok);
    ok &= em[k - t_len - 1].ct_eq(&0u8);

    for el in em.iter().skip(2).take(k - t_len - 3) {
        #[cfg(feature = "std")]
        println!("looking for 0xff: got {:x?} ok={:?}", el, ok);
        ok &= el.ct_eq(&0xff)
    }

    if ok.unwrap_u8() != 1 {
        return Err(Error::Verification);
    }

    Ok(())
}

/// prefix = 0x30 <oid_len + 8 + digest_len> 0x30 <oid_len + 4> 0x06 <oid_len> oid 0x05 0x00 0x04 <digest_len>
#[inline]
pub(crate) fn pkcs1v15_generate_prefix<D>() -> Prefix
where
    D: Digest + AssociatedOid,
{
    let oid = D::OID.as_bytes();
    let oid_len = oid.len() as u8;
    let digest_len = <D as Digest>::output_size() as u8;
    let mut v = Prefix::new();
    v.extend([
        0x30,
        oid_len + 8 + digest_len,
        0x30,
        oid_len + 4,
        0x6,
        oid_len,
    ]);
    v.extend_from_slice(oid);
    v.extend_from_slice(&[0x05, 0x00, 0x04, digest_len]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    #[test]
    fn test_non_zero_bytes() {
        for _ in 0..10 {
            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let mut b = vec![0u8; 512];
            non_zero_random_bytes(&mut rng, &mut b);
            for el in &b {
                assert_ne!(*el, 0u8);
            }
        }
    }
}
