//! Supported padding schemes.

use crate::errors::Result;
use crate::key::RsaPublicKey;
use num_traits::{Num, One, Unsigned, Zero};

/// Digital signature scheme.
pub trait SignatureScheme<T>
where
    T: Num + Unsigned + Zero + One + Clone + core::cmp::Eq,
{
    /// Verify a signed message.
    ///
    /// `hashed` must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    ///
    /// If the message is valid `Ok(())` is returned, otherwise an `Err` indicating failure.
    fn verify(self, pub_key: &RsaPublicKey<T>, hashed: &[u8], sig: &[u8]) -> Result<()>;
}
