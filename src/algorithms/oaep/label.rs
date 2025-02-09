use heapless::String;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const MAX_LABEL_LEN: usize = 128;

// Make a newtype wrapper for label String with String<128>
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Label(String<MAX_LABEL_LEN>);

impl Label {
    pub fn new(label: String<MAX_LABEL_LEN>) -> Self {
        Self(label)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<&str> for Label {
    fn from(label: &str) -> Self {
        Self(String::try_from(label).expect("Label is too long"))
    }
}

// Stub a serde deserialize for label
#[cfg(feature = "serde")]

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        todo!()
    }
}

#[cfg(feature = "serde")]
impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        todo!()
    }
}
