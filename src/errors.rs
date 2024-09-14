//! Error types.

/// Alias for [`core::result::Result`] with the `rsa` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error types
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid arguments.
    InvalidArguments,
}
