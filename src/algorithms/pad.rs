//! Special handling for converting the BigUint to u8 vectors

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use crypto_bigint::BoxedUint;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};
use crate::traits::UnsignedModularInt;
use core::borrow::Borrow;

/// Returns a new vector of the given length, with 0s left padded.
#[cfg(test)]
#[cfg(feature = "alloc")]
#[inline]
fn left_pad(input: &[u8], padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    left_pad_into(input, padded_len, &mut out)?;
    Ok(out)
}

#[inline]
pub fn left_pad_into<'a>(
    input: &[u8],
    padded_len: usize,
    storage: &'a mut [u8],
) -> Result<&'a [u8]> {
    if input.len() > padded_len {
        return Err(Error::InvalidPadLen);
    }

    let start = padded_len - input.len();
    {
        // Fallible slicing (`get_mut`/`split_at_mut_checked`) and a
        // byte-copy loop instead of `[..]` indexing + `copy_from_slice`,
        // so no `slice_index_fail` / `copy_from_slice` panic path is
        // synthesized into the (embedded) sign binary. `tail.len()` ==
        // `padded_len - start` == `input.len()`, so the zip copies all
        // of `input`.
        let region = storage
            .get_mut(..padded_len)
            .ok_or(Error::OutputBufferTooSmall)?;
        let (zeros, tail) = region
            .split_at_mut_checked(start)
            .ok_or(Error::InvalidPadLen)?;
        zeros.fill(0);
        for (dst, src) in tail.iter_mut().zip(input.iter()) {
            *dst = *src;
        }
    }
    storage.get(..padded_len).ok_or(Error::OutputBufferTooSmall)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// In some cases BoxedUint might already have leading zeroes, this function removes them
/// before padding again.
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    uint_to_be_pad_into(input, padded_len, &mut out)?;
    Ok(out)
}

#[inline]
pub fn uint_to_be_pad_into<T>(input: T, padded_len: usize, storage: &mut [u8]) -> Result<&[u8]>
where
    T: UnsignedModularInt,
{
    let leading_zeros = input.leading_zeros() as usize / 8;
    let bytes = input.to_be_bytes();
    let borrow: &[u8] = bytes.borrow();
    let trimmed = borrow.get(leading_zeros..).ok_or(Error::Internal)?;
    left_pad_into(trimmed, padded_len, storage)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// In some cases BoxedUint might already have leading zeroes, this function removes them
/// before padding again.
#[inline]
#[cfg(feature = "alloc")]
pub(crate) fn uint_to_zeroizing_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    uint_to_zeroizing_be_pad_into(input, padded_len, &mut out)?;
    Ok(out)
}

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
    let leading_zeros = input.leading_zeros() as usize / 8;
    let m = Zeroizing::new(input);
    let m = Zeroizing::new(m.to_be_bytes());
    let bytes: &[u8] = m.as_ref();
    let trimmed = bytes.get(leading_zeros..).ok_or(Error::Internal)?;
    left_pad_into(trimmed, padded_len, storage)
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;
    #[test]
    fn test_left_pad() {
        const INPUT_LEN: usize = 3;
        let input = vec![0u8; INPUT_LEN];

        // input len < padded len
        let padded = left_pad(&input, INPUT_LEN + 1).unwrap();
        assert_eq!(padded.len(), INPUT_LEN + 1);

        // input len == padded len
        let padded = left_pad(&input, INPUT_LEN).unwrap();
        assert_eq!(padded.len(), INPUT_LEN);

        // input len > padded len
        let padded = left_pad(&input, INPUT_LEN - 1);
        assert!(padded.is_err());
    }
}
