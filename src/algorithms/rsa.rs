//! Generic RSA implementation

use core::cmp::Ordering;

use num_traits::{FromPrimitive, One, Pow, Signed, Zero};
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use modmath::basic_mod_exp as mod_exp;

use crate::traits::modular::UnsignedModularInt;
use crate::traits::modular::{MontyParams,MontyForm};

use crate::errors::{Error, Result};
use crate::traits::keys::{PrivateKeyParts, PublicKeyParts};

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
/// Returns a plaintext `BoxedUint`. Performs RSA blinding if an `Rng` is passed.
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
    for<'a> &'a T: AsRef<T>,
{

    let n = priv_key.n();
    let d = priv_key.d();

    if c >= n.as_ref() {
        return Err(Error::Decryption);
    }

    let n_params = priv_key.n_params();
    let bits = d.bits_precision();

    let c = if let Some(ref mut rng) = rng {
        let (blinded, unblinder) = blind(rng, priv_key, c);
        blinded.widen(bits)
    } else {
        c.widen(bits)
    };

    let is_multiprime = priv_key.primes().len() > 2;

    todo!()
}

/// ⚠️ Performs raw RSA decryption with no padding.
///
/// Returns a plaintext `BoxedUint`. Performs RSA blinding if an `Rng` is passed.  This will also
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
where
    T: UnsignedModularInt,
    for<'a> &'a T: AsRef<T>,
{
    let m = rsa_decrypt(rng, priv_key, c)?;

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
    todo!()
}

/// Given an m and and unblinding factor, unblind the m.
fn unblind<T>(m: &T, unblinder: &T, n_params: &MontyParams<T>) -> T 
where
    T: UnsignedModularInt,
{
    // m * r^-1 (mod n)
    debug_assert_eq!(
        m.bits_precision(),
        unblinder.bits_precision(),
        "invalid unblinder"
    );

    debug_assert_eq!(
        m.bits_precision(),
        n_params.bits_precision(),
        "invalid n_params"
    );
    todo!()
}

/// Computes `base.pow_mod(exp, n)` with precomputed `n_params`.
fn pow_mod_params<T>(base: &T, exp: &T, n_params: &MontyParams<T>) -> T
where
    T: UnsignedModularInt,
{
    let base = reduce_vartime(base, n_params);
    base.pow(exp).retrieve()
}

fn reduce_vartime<T>(n: &T, p: &MontyParams<T>) -> MontyForm<T>
where
    T: UnsignedModularInt,
{
    let bits_precision = p.modulus().bits_precision();
    let modulus = p.modulus().clone();

    let n = match n.bits_precision().cmp(&bits_precision) {
        Ordering::Less => n.widen(bits_precision),
        Ordering::Equal => n.clone(),
        Ordering::Greater => n.shorten(bits_precision),
    };

    let n_reduced = n.rem_vartime(&modulus).widen(p.bits_precision());
    MontyForm::new(n_reduced, p.clone())
}

/// Computes `lhs.mul_mod(rhs, n)` with precomputed `n_params`.
fn mul_mod_params<T>(lhs: &T, rhs: &T, n_params: &MontyParams<T>) -> T 
where 
    T: UnsignedModularInt,
{
    todo!()
}

/// The following (deterministic) algorithm also recovers the prime factors `p` and `q` of a modulus `n`, given the
/// public exponent `e` and private exponent `d` using the method described in
/// [NIST 800-56B Appendix C.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf).
pub fn recover_primes<T>(
    n: &T,
    e: &T,
    d: &T,
) -> Result<(T, T)>
where
    T: UnsignedModularInt,
{
    // Check precondition

    // Note: because e is at most u64::MAX, it is already
    // known to be < 2**256
    if e <= &T::from(2u64.pow(16)).unwrap() {
        return Err(Error::InvalidArguments);
    }

    todo!()
}

/// Compute the modulus of a key from its primes.
pub(crate) fn compute_modulus<T>(primes: &[T]) -> T
where
    T: UnsignedModularInt
{
    let mut primes = primes.iter();
    let mut out = primes.next().expect("must at least be one prime").clone();
    for p in primes {
        out *= *p;
    }
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
    let bits = primes[0].bits_precision();
    let mut totient = T::one_with_precision(bits);

    for prime in primes {
        totient *= *prime - T::one();
    }
    let exp = exp.widen(totient.bits_precision());

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
    let one = T::one();
    let p1 = *p - one;
    let q1 = *q - one;

    // LCM inlined
    let gcd = p1.gcd(&q1);
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Reimplement this
    #[test]
    fn recover_primes_works() {
        /*
        let bits = 2048;

        let n = BoxedUint::from_be_hex("d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078cc780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf6776fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b", bits).unwrap();
        let e = BoxedUint::from(65_537u64);
        let d = BoxedUint::from_be_hex("c4e70c689162c94c660828191b52b4d8392115df486a9adbe831e458d73958320dc1b755456e93701e9702d76fb0b92f90e01d1fe248153281fe79aa9763a92fae69d8d7ecd144de29fa135bd14f9573e349e45031e3b76982f583003826c552e89a397c1a06bd2163488630d92e8c2bb643d7abef700da95d685c941489a46f54b5316f62b5d2c3a7f1bbd134cb37353a44683fdc9d95d36458de22f6c44057fe74a0a436c4308f73f4da42f35c47ac16a7138d483afc91e41dc3a1127382e0c0f5119b0221b4fc639d6b9c38177a6de9b526ebd88c38d7982c07f98a0efd877d508aae275b946915c02e2e1106d175d74ec6777f5e80d12c053d9c7be1e341", bits).unwrap();
        let p = BoxedUint::from_be_hex("f827bbf3a41877c7cc59aebf42ed4b29c32defcb8ed96863d5b090a05a8930dd624a21c9dcf9838568fdfa0df65b8462a5f2ac913d6c56f975532bd8e78fb07bd405ca99a484bcf59f019bbddcb3933f2bce706300b4f7b110120c5df9018159067c35da3061a56c8635a52b54273b31271b4311f0795df6021e6355e1a42e61", bits / 2).unwrap();
        let q = BoxedUint::from_be_hex("da4817ce0089dd36f2ade6a3ff410c73ec34bf1b4f6bda38431bfede11cef1f7f6efa70e5f8063a3b1f6e17296ffb15feefa0912a0325b8d1fd65a559e717b5b961ec345072e0ec5203d03441d29af4d64054a04507410cf1da78e7b6119d909ec66e6ad625bf995b279a4b3c5be7d895cd7c5b9c4c497fde730916fcdb4e41b", bits / 2).unwrap();

        let (mut p1, mut q1) = recover_primes(&NonZero::new(n).unwrap(), &e, &d).unwrap();

        if p1 < q1 {
            std::mem::swap(&mut p1, &mut q1);
        }
        assert_eq!(p, p1);
        assert_eq!(q, q1);
        */
    }
}
