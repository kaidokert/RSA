//! RSA-related trait definitions.

mod encryption;
pub(crate) mod keys;
pub(crate) mod modular;
mod padding;

pub use encryption::{Decryptor, EncryptingKeypair, RandomizedDecryptor, RandomizedEncryptor};
#[cfg(any(feature = "private-key", feature = "wip-private-key"))]
pub use keys::GenericPrivateKeyParts;
#[cfg(feature = "private-key")]
#[allow(deprecated)]
pub use keys::PrivateKeyParts;
#[cfg(not(feature = "private-key"))]
pub use keys::PublicKeyParts;
#[cfg(feature = "private-key")]
pub use keys::PublicKeyParts;
pub use modular::{FixedWidthUnsignedInt, IntegerResize, NonZero, Odd, UnsignedModularInt};
pub use padding::{PaddingScheme, SignatureScheme};
