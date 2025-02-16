//! `RSASSA-PKCS1-v1_5` signatures.

use ::signature::SignatureEncoding;
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
#[cfg(feature = "serde")]
use serdect::serde::{de, Deserialize, Serialize};

use crate::traits::UnsignedModularInt;

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
        let source_slice = bytes.as_mut();
        source_slice.copy_from_slice(&value[..source_slice.len()]);
        let result = T::from_be_bytes(&bytes);
        Ok(Self {
            inner: result,
            len: value.len(),
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
impl<T> Serialize for Signature<T> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        todo!()
    }
}

#[cfg(feature = "serde")]
impl<'de, T> Deserialize<'de> for Signature<T> {
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
        /*
        let signature = Signature {
            inner: BoxedUint::from(42u32),
        };

        let tokens = [Token::Str("000000000000002a")];
        assert_tokens(&signature.readable(), &tokens);
        */
    }
}
