//! RSA-related trait definitions.

mod encryption;
pub(crate) mod keys;
mod padding;

#[cfg(feature = "full")]
pub use encryption::{Decryptor, EncryptingKeypair, RandomizedDecryptor, RandomizedEncryptor};
#[cfg(not(feature = "full"))]
pub use encryption::{Decryptor, EncryptingKeypair, RandomizedEncryptor};
#[cfg(feature = "full")]
pub use keys::{PrivateKeyParts, PublicKeyParts};
#[cfg(not(feature = "full"))]
pub use keys::{PublicKeyParts};
pub use padding::{PaddingScheme, SignatureScheme};
