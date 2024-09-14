#![cfg_attr(not(test), no_std)]

mod algorithms;
pub mod errors;
pub mod traits;

mod key;

pub use crate::errors::{Error, Result};

pub mod hazmat;
