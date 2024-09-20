//! Special handling for converting the BigUint to u8 vectors

use zeroize::Zeroizing;

use crate::errors::{Error, Result};
use crate::traits::UnsignedModularInt;
use core::borrow::Borrow;

/// Returns a new vector of the given length, with 0s left padded.
#[inline]
fn left_pad<'a>(input: &[u8], padded_len: usize, storage: &'a mut [u8]) -> Result<&'a [u8]> {
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
#[inline]
pub(crate) fn uint_to_be_pad<T>(input: T, padded_len: usize, storage: &mut [u8]) -> Result<&[u8]>
where
    T: UnsignedModularInt + num_traits::ToBytes,
{
    let be_bytes = input.to_be_bytes();
    let borrow: &[u8] = be_bytes.borrow();
    left_pad(borrow, padded_len, storage)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad<T>(input: T, padded_len: usize) -> Result<()> {
    todo!()
}

#[cfg(test)]
mod tests {
    use core::borrow::Borrow;

    use super::*;

    #[test]
    fn test_left_pad() {
        const INPUT_LEN: usize = 3;
        let array = [1, 2, 3];
        let input = array.as_slice();

        let mut storage = [0x55u8; INPUT_LEN + 2];
        // input len < padded len
        let padded = left_pad(input, INPUT_LEN + 1, &mut storage).unwrap();
        assert_eq!(padded.len(), INPUT_LEN + 1);
        assert_eq!(padded, &[0, 1, 2, 3]);

        // input len == padded len
        let padded = left_pad(input, INPUT_LEN, &mut storage).unwrap();
        assert_eq!(padded.len(), INPUT_LEN);
        assert_eq!(padded, &[1, 2, 3]);

        // input len > padded len
        let padded = left_pad(&input, INPUT_LEN - 1, &mut storage);
        assert!(padded.is_err());

        let mut storage = [0u8; 1];
        let padded = left_pad(&input, INPUT_LEN - 1, &mut storage);
        assert!(padded.is_err());
    }

    #[test]
    fn test_uint_to_be_pad() {
        let mut storage = [0x55u8; 4];
        let padded = uint_to_be_pad(0xDEAD_u16, 3, &mut storage).unwrap();
        assert_eq!(padded, &[0x00, 0xDE, 0xAD]);

        let padded = uint_to_be_pad(0xDEADBEEF_u32, 4, &mut storage).unwrap();
        assert_eq!(padded, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
