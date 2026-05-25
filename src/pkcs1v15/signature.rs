//! `RSASSA-PKCS1-v1_5` signatures.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
#[cfg(feature = "alloc")]
use crypto_bigint::BoxedUint;
use signature::SignatureEncoding;

use crate::traits::UnsignedModularInt;

#[cfg(feature = "serde")]
use serdect::serde::{de, Deserialize, Serialize};
#[cfg(feature = "encoding")]
use spki::{
    der::{asn1::BitString, Result as DerResult},
    SignatureBitStringEncoding,
};

/// `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericSignature<T>
where
    T: UnsignedModularInt,
{
    pub(super) inner: T,
}

/// Owned signature byte buffer sized to match the underlying integer type `T`.
#[derive(Clone)]
pub struct SignatureBytes<T>(T::Bytes)
where
    T: UnsignedModularInt;

/// Boxed PKCS#1 v1.5 signature alias used by the `alloc` code path.
#[cfg(feature = "alloc")]
pub type Signature = GenericSignature<BoxedUint>;

impl<T> GenericSignature<T>
where
    T: UnsignedModularInt,
{
    /// Construct a signature from its underlying integer representation.
    pub fn from_inner(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the underlying integer representation.
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T> From<T> for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    fn from(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    fn new(inner: T::Bytes) -> Self {
        Self(inner)
    }
}

impl<T> AsRef<[u8]> for SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> core::ops::Deref for SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> From<GenericSignature<T>> for SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    fn from(signature: GenericSignature<T>) -> Self {
        Self::new(signature.inner.to_be_bytes())
    }
}

#[cfg(feature = "alloc")]
impl<T> TryFrom<&[u8]> for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Ok(Self {
            inner: T::try_from_be_bytes_vartime(bytes).map_err(signature::Error::from_source)?,
        })
    }
}

#[cfg(feature = "alloc")]
impl<T> SignatureEncoding for GenericSignature<T>
where
    T: UnsignedModularInt + 'static,
    T::Bytes: Clone + Send + Sync + 'static,
{
    type Repr = SignatureBytes<T>;
}

#[cfg(all(feature = "encoding", feature = "alloc"))]
impl<T> SignatureBitStringEncoding for GenericSignature<T>
where
    T: UnsignedModularInt + 'static,
    T::Bytes: Clone + Send + Sync + 'static,
{
    fn to_bitstring(&self) -> DerResult<BitString> {
        BitString::new(0, self.to_vec())
    }
}

#[cfg(feature = "alloc")]
impl From<GenericSignature<BoxedUint>> for Box<[u8]> {
    fn from(signature: GenericSignature<BoxedUint>) -> Box<[u8]> {
        SignatureBytes::<BoxedUint>::from(signature).0
    }
}

impl<T> LowerHex for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let bytes = self.inner.to_be_bytes();
        for byte in bytes.as_ref() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<T> UpperHex for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let bytes = self.inner.to_be_bytes();
        for byte in bytes.as_ref() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl<T> Display for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", self)
    }
}

#[cfg(feature = "serde")]
impl<T> Serialize for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        let bytes = self.inner.to_be_bytes();
        serdect::slice::serialize_hex_lower_or_bin(&bytes, serializer)
    }
}

#[cfg(all(feature = "serde", feature = "alloc"))]
impl<'de> Deserialize<'de> for GenericSignature<BoxedUint> {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        serdect::slice::deserialize_hex_or_bin_vec(deserializer)?
            .as_slice()
            .try_into()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(feature = "serde", feature = "alloc"))]
    fn test_serde() {
        use super::*;
        use serde_test::{assert_tokens, Configure, Token};
        let signature = GenericSignature::<BoxedUint> {
            inner: BoxedUint::from(42u32),
        };

        let tokens = [Token::Str("000000000000002a")];
        assert_tokens(&signature.readable(), &tokens);
    }
}
