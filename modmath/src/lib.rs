#![cfg_attr(not(feature = "std"), no_std)]

//! Modular math implemented with traits.
//!
//! This crate provides modular arithmetic implemented not for
//! any particular type, but for any type that implements minimal
//! set of `core::ops::` and `num_traits::` traits.
//!
//! All provided functions are simply free functions.
//!
//! There are three verions of each: `basic` that has least amount
//! of constraints, but requires `Copy` to be implemented for the type.
//! `constrained` requires `Clone`.
//! `strict` requires neither, but has most other constaints to be able to
//! operate with references and [`Overflowing`](https://docs.rs/num-traits/latest/num_traits/ops/overflowing) arithmetic.

//! Tested with builtin integers and [`num-bigint`](https://crates.io/crates/num-bigint), [`crypto-bigint`](https://crates.io/crates/crypto-bigint), [`bnum`](https://crates.io/crates/bnum), [`ibig`](https://crates.io/crates/ibig)
//! and [`fixed-bigint`](https://crates.io/crates/fixed-bigint) crates. `basic` versions of functions
//! wont work with `num-bigint` and `ibig` as both require heap
//! allocation.

mod add;
mod exp;
mod mul;
mod sub;

mod inv;
mod montgomery;

pub use add::{basic_mod_add, constrained_mod_add, strict_mod_add};
pub use exp::{basic_mod_exp, constrained_mod_exp, strict_mod_exp};
pub use inv::{basic_mod_inv, constrained_mod_inv, strict_mod_inv};
pub use montgomery::{
    basic_compute_montgomery_params, basic_compute_montgomery_params_with_method,
    basic_from_montgomery, basic_montgomery_mod_exp, basic_montgomery_mod_mul,
    basic_montgomery_mul, basic_to_montgomery, strict_compute_montgomery_params,
    strict_compute_montgomery_params_with_method, strict_from_montgomery,
    strict_montgomery_mod_exp, strict_montgomery_mod_mul, strict_to_montgomery, NPrimeMethod,
};
pub use mul::{basic_mod_mul, constrained_mod_mul, strict_mod_mul};
pub use sub::{basic_mod_sub, constrained_mod_sub, strict_mod_sub};

#[cfg(test)]
#[macro_export]
macro_rules! maybe_test {
    (on, $e:expr) => {
        $e
    };
    (off, $e:expr) => {
        ()
    };
}
