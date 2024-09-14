//! Traits related to the key components

use num_traits::{Num, One, Signed, Unsigned, Zero};
use zeroize::{DefaultIsZeroes, Zeroize};

/// Components of an RSA public key.
pub trait PublicKeyParts<T>
where
    T: Num + Zero + One + Unsigned,
{
    /// Returns the modulus of the key.
    fn n(&self) -> &T;

    /// Returns the public exponent of the key.
    fn e(&self) -> &T;

    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    fn size(&self) -> usize;
}

/// Components of an RSA private key.
pub trait PrivateKeyParts<T>: PublicKeyParts<T>
where
    T: Num + Zero + One + Unsigned + Clone + Signed + DefaultIsZeroes,
{
    /// Returns the private exponent of the key.
    fn d(&self) -> &T;

    /// Returns the prime factors.
    fn primes(&self) -> &[T];

    /// Returns the precomputed dp value, D mod (P-1)
    fn dp(&self) -> Option<&T>;

    /// Returns the precomputed dq value, D mod (Q-1)
    fn dq(&self) -> Option<&T>;

    /// Returns the precomputed qinv value, Q^-1 mod P.
    /// Since qinv can be negative, we use Signed trait here.
    fn qinv(&self) -> Option<&T>
    where
        T: Signed;

    /// Returns an iterator over the CRT Values
    fn crt_values(&self) -> Option<&[CrtValue<T>]>;
}

/// Contains the precomputed Chinese remainder theorem values.
#[derive(Debug, Clone)]
pub struct CrtValue<T>
where
    T: Signed + Clone + Zeroize,
{
    /// D mod (prime - 1)
    pub(crate) exp: T,
    /// R·Coeff ≡ 1 mod Prime.
    pub(crate) coeff: T,
    /// product of primes prior to this (inc p and q)
    pub(crate) r: T,
}

impl<T> Zeroize for CrtValue<T>
where
    T: Signed + Clone + Zeroize,
{
    fn zeroize(&mut self) {
        self.exp.zeroize();
        self.coeff.zeroize();
        self.r.zeroize();
    }
}

impl<T> Drop for CrtValue<T>
where
    T: Signed + Clone + Zeroize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_bits() {
        let _crt = CrtValue::<i64> {
            exp: 0,
            coeff: 0,
            r: 0,
        };
    }
}
