//! Special handling for converting the BigUint to u8 vectors

use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Returns a new vector of the given length, with 0s left padded.
#[inline]
fn left_pad(input: &[u8], padded_len: usize) -> Result<()> {
    if input.len() > padded_len {
        return Err(Error::InvalidPadLen);
    }

    todo!();
    Ok(())
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
#[inline]
pub(crate) fn uint_to_be_pad<T>(input: T, padded_len: usize) -> Result<()> {
    todo!()
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad<T>(input: T, padded_len: usize) -> Result<()> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
}
