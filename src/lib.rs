#![allow(unused_variables, unused_mut, unused_imports, dead_code)]
#![cfg_attr(not(test), no_std)]

//! # Supported algorithms
//!
//! This crate supports several schemes described in [RFC8017]:
//!
//! - [OAEP encryption scheme](#oaep-encryption)
//! - [PKCS#1 v1.5 encryption scheme](#pkcs1-v15-encryption)
//! - [PKCS#1 v1.5 signature scheme](#pkcs1-v15-signatures)
//! - [PSS signature scheme](#pss-signatures)
//!
//! These schemes are described below.
//!

#[cfg(feature = "std")]
extern crate std;

pub use rand_core;
pub use signature;

mod algorithms;
pub mod errors;
pub mod oaep;
pub mod pkcs1v15;
pub mod pss;
pub mod traits;

mod dummy_rng;
mod key;

mod prefix;

#[cfg(feature = "sha2")]
pub use sha2;

pub use crate::{
    errors::{Error, Result},
    key::{RsaPrivateKey, RsaPublicKey},
    oaep::Oaep,
    pkcs1v15::{Pkcs1v15Encrypt, Pkcs1v15Sign},
    prefix::Prefix,
    pss::Pss,
    traits::keys::CrtValue,
};

#[cfg(feature = "hazmat")]
pub mod hazmat;
