//! Useful algorithms related to RSA.

#[cfg(feature = "full")]
mod mgf;

#[cfg(feature = "alloc")]
pub(crate) mod generate;
#[cfg(feature = "full")]
pub(crate) mod oaep;
pub(crate) mod pad;
#[cfg(not(feature = "hack"))]
pub(crate) mod pkcs1v15;
#[cfg(feature = "alloc")]
pub(crate) mod pss;
#[cfg(not(feature = "hack"))]
pub(crate) mod rsa;
