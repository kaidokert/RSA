//! `RSASSA-PKCS1-v1_5` signatures.

#[cfg(feature = "alloc")]
use crate::RsaPublicKey;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
#[cfg(feature = "alloc")]
use crypto_bigint::BoxedUint;
use signature::SignatureEncoding;

use crate::traits::UnsignedModularInt;

#[cfg(feature = "serde")]
use serdect::serde::{Deserialize, Serialize, de};
#[cfg(feature = "encoding")]
use spki::{
    SignatureBitStringEncoding,
    der::{
        Result as DerResult,
        asn1::{BitString, BitStringRef},
    },
};

/// `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// Decoding with `TryFrom` or serde accepts at most [`Self::MAX_LEN`] bytes.
/// Use [`Self::from_bytes_with_max_len`] to explicitly allow larger signatures.
/// A signature's exact length and value are checked during verification.
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericSignature<T>
where
    T: UnsignedModularInt,
{
    pub(super) inner: T,
    /// Encoded length in bytes, at most the byte width of `inner`.
    len: usize,
}

/// Owned signature byte buffer sized to match the underlying integer type `T`.
#[derive(Clone)]
pub struct SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    bytes: T::Bytes,
    start: usize,
}

impl<T> Debug for SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SignatureBytes")
            .field(&self.as_ref())
            .finish()
    }
}

/// Boxed PKCS#1 v1.5 signature alias used by the `alloc` code path.
#[cfg(feature = "alloc")]
pub type Signature = GenericSignature<BoxedUint>;

impl<T> GenericSignature<T>
where
    T: UnsignedModularInt,
{
    /// Default maximum encoded signature length in bytes.
    ///
    /// Corresponds to the default maximum modulus size, [`RsaPublicKey::MAX_SIZE`].
    #[cfg(feature = "alloc")]
    pub const MAX_LEN: usize = RsaPublicKey::MAX_SIZE.div_ceil(8);

    /// Decode a signature with an explicit maximum encoded length in bytes.
    ///
    /// The length is checked before allocating. This can be used to accept signatures
    /// for keys larger than [`RsaPublicKey::MAX_SIZE`], or to impose a smaller limit.
    /// The exact length and value are checked against the key during verification.
    ///
    /// Signatures larger than [`Self::MAX_LEN`] must also use this method when
    /// decoding their serialized bytes again. `TryFrom` and serde use the default limit.
    ///
    /// # Errors
    /// Returns an error if `bytes.len()` exceeds `max_len`.
    #[cfg(feature = "alloc")]
    pub fn from_bytes_with_max_len(bytes: &[u8], max_len: usize) -> signature::Result<Self> {
        if bytes.len() > max_len {
            return Err(signature::Error::new());
        }

        let inner = T::try_from_be_bytes_vartime(bytes).map_err(signature::Error::from_source)?;
        Ok(Self::with_len(inner, bytes.len()))
    }

    /// Construct a signature from its underlying integer representation.
    ///
    /// The signature encodes to the full byte width of `T`.
    pub fn from_inner(inner: T) -> Self {
        Self::with_len(inner, usize::MAX)
    }

    /// Construct a signature that encodes to `len` bytes, clamped to the byte width of `inner`.
    fn with_len(inner: T, len: usize) -> Self {
        let len = len.min(inner.to_be_bytes().as_ref().len());
        Self { inner, len }
    }

    /// Big-endian encoding of exactly the signature's encoded length.
    fn to_signature_bytes(&self) -> SignatureBytes<T> {
        let bytes = self.inner.to_be_bytes();
        let start = bytes.as_ref().len().saturating_sub(self.len);
        SignatureBytes { bytes, start }
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
        Self::from_inner(inner)
    }
}

impl<T> AsRef<[u8]> for SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    fn as_ref(&self) -> &[u8] {
        let bytes = self.bytes.as_ref();
        bytes.get(self.start..).unwrap_or(bytes)
    }
}

impl<T> core::ops::Deref for SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl<T> From<GenericSignature<T>> for SignatureBytes<T>
where
    T: UnsignedModularInt,
{
    fn from(signature: GenericSignature<T>) -> Self {
        signature.to_signature_bytes()
    }
}

#[cfg(feature = "alloc")]
impl<T> TryFrom<&[u8]> for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Self::from_bytes_with_max_len(bytes, Self::MAX_LEN)
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
        Box::from(signature.to_signature_bytes().as_ref())
    }
}

#[cfg(feature = "encoding")]
impl<T> TryFrom<BitStringRef<'_>> for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    type Error = signature::Error;

    fn try_from(bit_string: BitStringRef<'_>) -> signature::Result<Self> {
        Self::try_from(bit_string.as_bytes().ok_or_else(signature::Error::new)?)
    }
}

impl<T> LowerHex for GenericSignature<T>
where
    T: UnsignedModularInt,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.to_signature_bytes().as_ref() {
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
        for byte in self.to_signature_bytes().as_ref() {
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.to_signature_bytes(), serializer)
    }
}

#[cfg(all(feature = "serde", feature = "alloc"))]
impl<'de> Deserialize<'de> for GenericSignature<BoxedUint> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut buffer = [0u8; Self::MAX_LEN];
        serdect::slice::deserialize_hex_or_bin(&mut buffer, deserializer)?
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
        use serde_test::{Configure, Token, assert_tokens};
        let signature = GenericSignature::from_inner(BoxedUint::from(42u32));

        let tokens = [Token::Str("000000000000002a")];
        assert_tokens(&signature.readable(), &tokens);
    }
}
