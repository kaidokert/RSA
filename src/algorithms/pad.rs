//! Special handling for converting the BigUint to u8 vectors

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use crypto_bigint::BoxedUint;
use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};
use crate::traits::UnsignedModularInt;
use core::borrow::Borrow;

/// Writes the big-endian encoding of `bytes` into a buffer of exactly `padded_len` bytes
///
/// Constant-time with respect to the *value*: the only branches depend on the public lengths
/// The previous implementation sliced at `leading_zeros() / 8`, so the amount of data copied (and
/// whether an error was returned) depended on how many leading zero bytes the secret plaintext
/// had, which is exactly the signal the Marvin attack measures
///
/// Uses checked splits and byte-copy loops instead of `split_at` / `copy_from_slice`, so no
/// panic path is synthesized into the embedded sign binary.
#[inline]
fn be_pad_into(bytes: &[u8], out: &mut [u8]) -> Result<()> {
    let padded_len = out.len();
    if bytes.len() >= padded_len {
        let (hi, lo) = bytes
            .split_at_checked(bytes.len() - padded_len)
            .ok_or(Error::Internal)?;
        let overflow = hi.iter().fold(0u8, |acc, b| acc | b);
        for (dst, src) in out.iter_mut().zip(lo) {
            *dst = *src;
        }
        if core::hint::black_box(overflow) != 0 {
            out.zeroize();
            return Err(Error::InvalidPadLen);
        }
    } else {
        let (zero, tail) = out
            .split_at_mut_checked(padded_len - bytes.len())
            .ok_or(Error::Internal)?;
        zero.fill(0);
        for (dst, src) in tail.iter_mut().zip(bytes) {
            *dst = *src;
        }
    }
    Ok(())
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    be_pad_into(&input.to_be_bytes(), &mut out)?;
    Ok(out)
}

/// Writes `input` big-endian into the first `padded_len` bytes of `storage`, with 0s left padded.
#[inline]
pub fn uint_to_be_pad_into<T>(input: T, padded_len: usize, storage: &mut [u8]) -> Result<&[u8]>
where
    T: UnsignedModularInt,
{
    let bytes = input.to_be_bytes();
    let out = storage
        .get_mut(..padded_len)
        .ok_or(Error::OutputBufferTooSmall)?;
    be_pad_into(bytes.borrow(), out)?;
    Ok(out)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
///
/// For secret values: every intermediate buffer, including the returned one, is zeroized on drop.
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad(
    input: BoxedUint,
    padded_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let input = Zeroizing::new(input);
    let bytes = Zeroizing::new(input.to_be_bytes());
    let mut out = Zeroizing::new(vec![0u8; padded_len]);
    be_pad_into(&bytes, &mut out)?;
    Ok(out)
}

/// As [`uint_to_be_pad_into`], for secret values: the intermediate buffers are zeroized on drop.
#[inline]
pub fn uint_to_zeroizing_be_pad_into<T>(
    input: T,
    padded_len: usize,
    storage: &mut [u8],
) -> Result<&[u8]>
where
    T: UnsignedModularInt,
    T::Bytes: zeroize::Zeroize,
{
    let input = Zeroizing::new(input);
    let bytes = Zeroizing::new(input.to_be_bytes());
    let out = storage
        .get_mut(..padded_len)
        .ok_or(Error::OutputBufferTooSmall)?;
    be_pad_into(bytes.as_ref(), out)?;
    Ok(out)
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;
    #[test]
    fn be_pad() {
        let x = BoxedUint::from(0x0102u64);
        let p = uint_to_be_pad(x.clone(), 16).unwrap();
        assert_eq!(&p[..14], &[0u8; 14]);
        assert_eq!(&p[14..], &[1, 2]);

        let p = uint_to_zeroizing_be_pad(x.clone(), 3).unwrap();
        assert_eq!(&p[..], &[0, 1, 2]);

        let p = uint_to_be_pad(x.clone(), 8).unwrap();
        assert_eq!(&p[..], &[0, 0, 0, 0, 0, 0, 1, 2]);

        assert!(uint_to_be_pad(x.clone(), 1).is_err());
        assert!(uint_to_zeroizing_be_pad(x, 1).is_err());

        let p = uint_to_be_pad(BoxedUint::zero_with_precision(128), 4).unwrap();
        assert_eq!(&p[..], &[0u8; 4]);
    }
}
