//! Error types.

/// Alias for [`core::result::Result`] with the `rsa` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error types
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid padding scheme.
    InvalidPaddingScheme,

    /// Decryption error.
    Decryption,

    /// Verification error.
    Verification,

    /// Message too long.
    MessageTooLong,

    /// Input must be hashed.
    InputNotHashed,

    /// Number of primes must be 2 or greater.
    NprimesTooSmall,

    /// Too few primes of a given length to generate an RSA key.
    TooFewPrimes,

    /// Invalid prime value.
    InvalidPrime,

    /// Invalid modulus.
    InvalidModulus,

    /// Invalid exponent.
    InvalidExponent,

    /// Invalid coefficient.
    InvalidCoefficient,

    /// Modulus too large.
    ModulusTooLarge,

    /// Public exponent too small.
    PublicExponentTooSmall,

    /// Public exponent too large.
    PublicExponentTooLarge,

    /// Internal error.
    Internal,

    /// Label too long.
    LabelTooLong,

    /// Invalid padding length.
    InvalidPadLen,

    /// Invalid arguments.
    InvalidArguments,

    /// Output buffer too small
    OutputBufferTooSmall,
}

#[cfg(not(feature = "std"))]
impl From<Error> for signature::Error {
    fn from(_err: Error) -> Self {
        Self::new()
    }
}
