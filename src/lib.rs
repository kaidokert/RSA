#![cfg_attr(not(test), no_std)]

#[cfg(feature = "std")]
extern crate std;

mod algorithms;
pub mod errors;
pub mod pkcs1v15;
pub mod traits;

mod key;

pub use crate::{
    errors::{Error, Result},
    key::RsaPublicKey,
    pkcs1v15::{Pkcs1v15Encrypt, Pkcs1v15Sign},
    traits::keys::CrtValue,
};

#[cfg(feature = "hazmat")]
pub mod hazmat;
