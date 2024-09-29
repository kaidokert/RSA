//! `RSASSA-PKCS1-v1_5` signatures.

use crate::{algorithms::pad::uint_to_be_pad, traits::UnsignedModularInt};

/// `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Clone, PartialEq, Eq)]
pub struct Signature<T> {
    pub(super) inner: T,
    pub(super) len: usize,
}

impl<T> TryFrom<&[u8]> for Signature<T>
where
    T: UnsignedModularInt,
    <T as num_traits::FromBytes>::Bytes: num_traits::ops::bytes::NumBytes + Default,
{
    type Error = signature::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut bytes = <T as num_traits::FromBytes>::Bytes::default();
        bytes.as_mut().copy_from_slice(value);
        let result = T::from_be_bytes(&bytes);
        Ok(Self {
            inner: result,
            len: value.len(),
        })
    }
}

#[cfg(test)]
mod tests {}
