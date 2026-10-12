//! Special handling for converting the BigUint to u8 vectors

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use crypto_bigint::{BoxedUint, Choice, CtEq};
use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};
use crate::traits::UnsignedModularInt;
use core::borrow::Borrow;

/// Writes the big-endian encoding of `bytes` into `out`.
///
/// The value must fit in `out`: any bytes truncated from the front must be zero.
/// In release builds, the amount of data copied depends only on the slice lengths.
#[cfg(feature = "alloc")]
#[inline]
fn be_pad_into(bytes: &[u8], out: &mut [u8]) {
    let excess = bytes.len().saturating_sub(out.len());
    debug_assert!(
        !bytes[..excess]
            .iter()
            .fold(Choice::FALSE, |overflow, byte| overflow | !byte.ct_eq(&0u8))
            .to_bool(),
        "integer exceeds output width"
    );

    out.fill(0);
    let tail = &bytes[excess..];
    let start = out.len() - tail.len();
    out[start..].copy_from_slice(tail);
}

/// Fallible, panic-free form of [`be_pad_into`] for the no-alloc `*_into` functions.
///
/// Returns [`Error::InvalidPadLen`] and zeroizes `out` if the value does not fit. Constant-time
/// with respect to the *value*: the only branches depend on the public lengths. Uses checked
/// splits and byte-copy loops instead of `split_at` / `copy_from_slice`, so no panic path is
/// synthesized into the embedded sign binary.
#[inline]
fn try_be_pad_into(bytes: &[u8], out: &mut [u8]) -> Result<()> {
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
///
/// `input` must fit in `padded_len` bytes.
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; padded_len];
    be_pad_into(&input.to_be_bytes(), &mut out);
    out
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
    try_be_pad_into(bytes.borrow(), out)?;
    Ok(out)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
///
/// `input` must fit in `padded_len` bytes.
///
/// For secret values: every intermediate buffer, including the returned one, is zeroized on drop.
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad(input: BoxedUint, padded_len: usize) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    let bytes = Zeroizing::new(input.to_be_bytes());
    let mut out = Zeroizing::new(vec![0u8; padded_len]);
    be_pad_into(&bytes, &mut out);
    out
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
    try_be_pad_into(bytes.as_ref(), out)?;
    Ok(out)
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;
    #[test]
    fn be_pad() {
        let x = BoxedUint::from(0x0102u64);
        let p = uint_to_be_pad(x.clone(), 16);
        assert_eq!(&p[..14], &[0u8; 14]);
        assert_eq!(&p[14..], &[1, 2]);

        let p = uint_to_zeroizing_be_pad(x.clone(), 3);
        assert_eq!(&p[..], &[0, 1, 2]);

        let p = uint_to_be_pad(x.clone(), 8);
        assert_eq!(&p[..], &[0, 0, 0, 0, 0, 0, 1, 2]);

        let p = uint_to_be_pad(BoxedUint::zero_with_precision(128), 4);
        assert_eq!(&p[..], &[0u8; 4]);
    }

    #[test]
    fn try_be_pad() {
        let x = BoxedUint::from(0x0102u64);
        let mut storage = [0xffu8; 16];
        let p = uint_to_be_pad_into(x.clone(), 3, &mut storage).unwrap();
        assert_eq!(p, &[0, 1, 2]);

        let p = uint_to_zeroizing_be_pad_into(x.clone(), 8, &mut storage).unwrap();
        assert_eq!(p, &[0, 0, 0, 0, 0, 0, 1, 2]);

        assert_eq!(
            uint_to_be_pad_into(x.clone(), 1, &mut storage),
            Err(Error::InvalidPadLen)
        );
        assert_eq!(storage[0], 0);
        assert_eq!(
            uint_to_zeroizing_be_pad_into(x.clone(), 17, &mut storage),
            Err(Error::OutputBufferTooSmall)
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "integer exceeds output width")]
    fn be_pad_rejects_broken_precondition() {
        uint_to_zeroizing_be_pad(BoxedUint::from(0x0102u64), 1);
    }
}
