//! Fixed-capacity OAEP label for no_alloc contexts.

#![allow(missing_docs)]

use core::ops::Deref;
use heapless::String;

/// 128 is well below RFC 8017's `2^61` cap and comfortably under the
/// payload room of any usable RSA modulus.
pub const MAX_LABEL_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Label(String<MAX_LABEL_LEN>);

impl Label {
    pub fn new(label: String<MAX_LABEL_LEN>) -> Self {
        Self(label)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for Label {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<&str> for Label {
    /// Panics if `label` exceeds `MAX_LABEL_LEN` bytes.
    fn from(label: &str) -> Self {
        Self(String::try_from(label).expect("OAEP label exceeds MAX_LABEL_LEN"))
    }
}
