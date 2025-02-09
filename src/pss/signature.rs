//! `RSASSA-PSS` signatures.

use crate::algorithms::pad::uint_to_be_pad;
use ::signature::SignatureEncoding;
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
#[cfg(feature = "serde")]
use serdect::serde::{de, Deserialize, Serialize};
use crate::traits::UnsignedModularInt;

/// `RSASSA-PSS` signatures as described in [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Clone, PartialEq, Eq)]
pub struct Signature<T>
where
    T: UnsignedModularInt,
{
    pub(super) inner: T,
    pub(super) len: usize,
}

impl<T> TryFrom<&[u8]> for Signature<T>
where
    T: UnsignedModularInt,
    <T as num_traits::FromBytes>::Bytes: num_traits::ops::bytes::NumBytes + Default,
{
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        let mut bytes2 = <T as num_traits::FromBytes>::Bytes::default();
        bytes2.as_mut().copy_from_slice(bytes);
        let result = T::from_be_bytes(&bytes2);
        Ok(Self {
            inner: result,
            len: bytes.len(),
        })
    }
}

impl<T> Debug for Signature<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, fmt: &mut Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        todo!()
    }
}

impl<T> LowerHex for Signature<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

impl<T> UpperHex for Signature<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

impl<T> Display for Signature<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", self)
    }
}

#[cfg(feature = "serde")]
impl<T> Serialize for Signature<T>
where
    T: UnsignedModularInt,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        todo!()
    }
}

#[cfg(feature = "serde")]
impl<'de,T> Deserialize<'de> for Signature<T>
where
    T: UnsignedModularInt,
{
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use serde_test::{assert_tokens, Configure, Token};
        let signature = Signature {
            inner: BigUint::new(Vec::from([42])),
            len: 1,
        };

        let tokens = [Token::Str("2a")];
        assert_tokens(&signature.readable(), &tokens);
    }
}
