//! Useful algorithms related to RSA.

#[cfg(feature = "alloc")]
mod mgf;

#[cfg(feature = "alloc")]
pub(crate) mod generate;
#[cfg(feature = "alloc")]
pub(crate) mod oaep;
pub(crate) mod pad;
pub(crate) mod pkcs1v15;
#[cfg(feature = "alloc")]
pub(crate) mod pss;
pub(crate) mod rsa;
