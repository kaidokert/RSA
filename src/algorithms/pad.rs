//! Special handling for converting the BigUint to u8 vectors

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};

use core::borrow::Borrow;

pub trait NumBytes : core::borrow::Borrow<[u8]>  + Zeroize + AsRef<[u8]> 
{
}

impl NumBytes for [u8; 1] {}

pub trait UnsignedModularInt : Zeroize {
    type Bytes: NumBytes;
    fn leading_zeros(&self) -> u32;
    fn to_be_bytes(&self) -> Self::Bytes;
}

impl UnsignedModularInt for u8 {
    type Bytes = [u8; 1];
    fn leading_zeros(&self) -> u32 {
        u8::leading_zeros(*self)
    }
    fn to_be_bytes(&self) -> Self::Bytes {
        u8::to_be_bytes(*self)
    }
}

#[cfg(feature = "alloc")]
impl NumBytes for alloc::boxed::Box<[u8]> {}

#[cfg(feature = "alloc")]
impl UnsignedModularInt for BoxedUint {
    type Bytes = alloc::boxed::Box<[u8]>;
    fn leading_zeros(&self) -> u32 {
        self.leading_zeros()
    }
    fn to_be_bytes(&self) -> Self::Bytes {
        self.as_words()
            .iter()
            .rev()
            .flat_map(|word| word.to_be_bytes())
            .collect::<Vec<u8>>()
            .into_boxed_slice()
    }
}

/// Returns a new vector of the given length, with 0s left padded.
/// Returns a new vector of the given length, with 0s left padded.
#[cfg(test)]
#[cfg(feature = "alloc")]
#[inline]
fn left_pad(input: &[u8], padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    left_pad_noalloc(input, padded_len, &mut out)?;
    Ok(out)
}

#[inline]
fn left_pad_noalloc<'a>(input: &[u8], padded_len: usize, storage: &'a mut [u8]) -> Result<&'a [u8]> {
    if input.len() > padded_len {
        return Err(Error::InvalidPadLen);
    }

    if storage.len() < padded_len {
        return Err(Error::OutputBufferTooSmall);
    }

    let start = padded_len - input.len();
    for byte in &mut storage[..start] {
        *byte = 0;
    }
    storage[start..start + input.len()].copy_from_slice(input);
    Ok(&storage[..padded_len])
}


/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// In some cases BoxedUint might already have leading zeroes, this function removes them
/// before padding again.
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    uint_to_be_pad_noalloc(input, padded_len, &mut out)?;
    Ok(out)
}

#[inline]
pub fn uint_to_be_pad_noalloc<T>(input: T, padded_len: usize, storage: &mut [u8]) -> Result<&[u8]>
where
    T: UnsignedModularInt
{
    let leading_zeros = input.leading_zeros() as usize / 8;
    let bytes = input.to_be_bytes();
    let borrow: &[u8] = bytes.borrow();
    left_pad_noalloc(&borrow[leading_zeros..], padded_len, storage)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// In some cases BoxedUint might already have leading zeroes, this function removes them
/// before padding again.
#[inline]
#[cfg(feature = "alloc")]
pub(crate) fn uint_to_zeroizing_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    uint_to_zeroizing_be_pad_noalloc(input, padded_len, &mut out)?;
    Ok(out)
}

#[inline]
pub fn uint_to_zeroizing_be_pad_noalloc<T>(
    input: T,
    padded_len: usize,
    storage: &mut [u8],
) -> Result<&[u8]>
where
    T: UnsignedModularInt
{
    let leading_zeros = input.leading_zeros() as usize / 8;
    let m = Zeroizing::new(input);
    let m = Zeroizing::new(m.to_be_bytes());
    let bytes: &[u8] = m.as_ref().as_ref();
    left_pad_noalloc(&bytes[leading_zeros..], padded_len, storage)
}

#[cfg(test)]
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
