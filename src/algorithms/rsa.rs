//! Generic RSA implementation

use num_traits::{FromPrimitive, One, Pow, Signed, Zero};
use zeroize::{Zeroize, Zeroizing};

use super::modular::exp::mod_exp;
use crate::traits::modular::UnsignedModularInt;

use crate::errors::{Error, Result};
use crate::traits::{PrivateKeyParts, PublicKeyParts};

/// ⚠️ Raw RSA encryption of m with the public key. No padding is performed.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.
#[inline]
pub fn rsa_encrypt<K, T>(key: &K, m: T) -> T
where
    K: PublicKeyParts<T>, // Public key trait with generic type T
    T: UnsignedModularInt,
{
    mod_exp(m, *key.e(), *key.n()) // Perform modular exponentiation
}

/// ⚠️ Performs raw RSA decryption with no padding or error checking.
///
/// Returns a plaintext `BigUint`. Performs RSA blinding if an `Rng` is passed.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.

fn rsa_decrypt() {
    todo!()
}

/// ⚠️ Performs raw RSA decryption with no padding.
///
/// Returns a plaintext `BigUint`. Performs RSA blinding if an `Rng` is passed.  This will also
/// check for errors in the CRT computation.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.

fn rsa_decrypt_and_check() {
    todo!()
}

/// Returns the blinded c, along with the unblinding factor.

fn blind() {
    todo!()
}

/// Given an m and and unblinding factor, unblind the m.
fn unblind<T>(key: &impl PublicKeyParts<T>, m: &T, unblinder: &T) -> T
where
    T: UnsignedModularInt,
{
    (*m * *unblinder) % *key.n()
}

/// The following (deterministic) algorithm also recovers the prime factors `p` and `q` of a modulus `n`, given the
/// public exponent `e` and private exponent `d` using the method described in
/// [NIST 800-56B Appendix C.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf).
pub fn recover_primes<T>(n: &T, e: &T, d: &T) -> Result<(T, T)> {
    // Check precondition
    todo!()
}

/// Compute the modulus of a key from its primes.
pub(crate) fn compute_modulus<T>(primes: &[T]) -> T {
    todo!()
}

/// Compute the private exponent from its primes (p and q) and public exponent
/// This uses Euler's totient function
#[inline]
pub(crate) fn compute_private_exponent_euler_totient<T>(primes: &[T], exp: &T) -> Result<T>
where
    T: UnsignedModularInt,
{
    if primes.len() < 2 {
        return Err(Error::InvalidPrime);
    }

    let mut totient = T::one();

    for prime in primes {
        totient = totient * (*prime - T::one());
    }

    // NOTE: `mod_inverse` checks if `exp` evenly divides `totient` and returns `None` if so.
    // This ensures that `exp` is not a factor of any `(prime - 1)`.
    todo!()
}

/// Compute the private exponent from its primes (p and q) and public exponent
///
/// This is using the method defined by
/// [NIST 800-56B Section 6.2.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf#page=47).
/// (Carmichael function)
///
/// FIPS 186-4 **requires** the private exponent to be less than λ(n), which would
/// make Euler's totiem unreliable.
#[inline]
pub(crate) fn compute_private_exponent_carmicheal<T>(p: &T, q: &T, exp: &T) -> Result<T>
where
    T: UnsignedModularInt,
{
    let p1 = *p - T::one();
    let q1 = *q - T::one();
    todo!()
}

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::*;
}
