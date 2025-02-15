//! Generic RSA implementation

use num_traits::{FromPrimitive, One, Pow, Signed, Zero};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};

use modmath::basic_mod_exp as mod_exp;

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
#[inline]
pub fn rsa_decrypt<T, R: CryptoRngCore + ?Sized>(
    mut rng: Option<&mut R>,
    priv_key: &impl PrivateKeyParts<T>,
    c: &T,
) -> Result<T>
where
    T: UnsignedModularInt,
{
    if c >= priv_key.n() {
        return Err(Error::Decryption);
    }

    if priv_key.n().is_zero() {
        return Err(Error::Decryption);
    }

    let c = if let Some(ref mut rng) = rng {
        let (blinded, unblinder) = blind(rng, priv_key, c);
        blinded
    } else {
        *c
    };

    let dp = priv_key.dp();
    let dq = priv_key.dq();
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
#[inline]
pub fn rsa_decrypt_and_check<T, R: CryptoRngCore + ?Sized>(
    priv_key: &impl PrivateKeyParts<T>,
    rng: Option<&mut R>,
    c: &T,
) -> Result<T> 
where T: UnsignedModularInt
{
    todo!()
}

/// Returns the blinded c, along with the unblinding factor.
fn blind<T, R: CryptoRngCore, K: PublicKeyParts<T>>(rng: &mut R, key: &K, c: &T) -> (T, T)
where
    T: UnsignedModularInt,
{
    // Blinding involves multiplying c by r^e.
    // Then the decryption operation performs (m^e * r^e)^d mod n
    // which equals mr mod n. The factor of r can then be removed
    // by multiplying by the multiplicative inverse of r.

    let mut r: T;
    let mut ir: Option<T>;
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

    // TODO: Reimplement this
    #[test]
    fn recover_primes_works() {
        /*
        let n = BigUint::parse_bytes(b"00d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078cc780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf6776fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b", 16).unwrap();
        let e = BigUint::from_u64(65537).unwrap();
        let d = BigUint::parse_bytes(b"00c4e70c689162c94c660828191b52b4d8392115df486a9adbe831e458d73958320dc1b755456e93701e9702d76fb0b92f90e01d1fe248153281fe79aa9763a92fae69d8d7ecd144de29fa135bd14f9573e349e45031e3b76982f583003826c552e89a397c1a06bd2163488630d92e8c2bb643d7abef700da95d685c941489a46f54b5316f62b5d2c3a7f1bbd134cb37353a44683fdc9d95d36458de22f6c44057fe74a0a436c4308f73f4da42f35c47ac16a7138d483afc91e41dc3a1127382e0c0f5119b0221b4fc639d6b9c38177a6de9b526ebd88c38d7982c07f98a0efd877d508aae275b946915c02e2e1106d175d74ec6777f5e80d12c053d9c7be1e341", 16).unwrap();
        let p = BigUint::parse_bytes(b"00f827bbf3a41877c7cc59aebf42ed4b29c32defcb8ed96863d5b090a05a8930dd624a21c9dcf9838568fdfa0df65b8462a5f2ac913d6c56f975532bd8e78fb07bd405ca99a484bcf59f019bbddcb3933f2bce706300b4f7b110120c5df9018159067c35da3061a56c8635a52b54273b31271b4311f0795df6021e6355e1a42e61",16).unwrap();
        let q = BigUint::parse_bytes(b"00da4817ce0089dd36f2ade6a3ff410c73ec34bf1b4f6bda38431bfede11cef1f7f6efa70e5f8063a3b1f6e17296ffb15feefa0912a0325b8d1fd65a559e717b5b961ec345072e0ec5203d03441d29af4d64054a04507410cf1da78e7b6119d909ec66e6ad625bf995b279a4b3c5be7d895cd7c5b9c4c497fde730916fcdb4e41b", 16).unwrap();

        let (mut p1, mut q1) = recover_primes(&n, &e, &d).unwrap();

        if p1 < q1 {
            std::mem::swap(&mut p1, &mut q1);
        }
        assert_eq!(p, p1);
        assert_eq!(q, q1);
         */
    }
}
