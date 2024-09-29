//! `RSASSA-PSS` signatures.

use crate::algorithms::pad::uint_to_be_pad;
use ::signature::SignatureEncoding;
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};

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
{
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        todo!()
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
