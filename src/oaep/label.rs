//! Fixed-capacity OAEP label for no_alloc contexts.

#![allow(missing_docs)]

use core::ops::Deref;
use heapless::Vec;

/// 128 is well below RFC 8017's `2^61` cap and comfortably under the
/// payload room of any usable RSA modulus.
pub const MAX_LABEL_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Label(Vec<u8, MAX_LABEL_LEN>);

impl Label {
    pub fn new(label: Vec<u8, MAX_LABEL_LEN>) -> Self {
        Self(label)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Deref for Label {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl TryFrom<&[u8]> for Label {
    type Error = crate::Error;

    fn try_from(label: &[u8]) -> Result<Self, Self::Error> {
        Vec::from_slice(label)
            .map(Self)
            .map_err(|_| crate::Error::LabelTooLong)
    }
}
