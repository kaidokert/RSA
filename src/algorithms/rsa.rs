use num_traits::{Num, One, PrimInt, Unsigned, Zero};

use crate::traits::PublicKeyParts;

// Generic function for RSA modular exponentiation
pub fn mod_exp<T>(base: T, exponent: T, modulus: T) -> T
where
    T: PrimInt + Num + Zero + One,
{
    let mut result = T::one();
    let mut base = base % modulus;
    let mut exp = exponent;

    while exp > T::zero() {
        // If exp is odd, multiply base with the result
        if exp % T::from(2).unwrap() == T::one() {
            result = (result * base) % modulus;
        }
        // Square the base and halve the exponent
        base = (base * base) % modulus;
        exp = exp / T::from(2).unwrap();
    }

    result
}

// Generic RSA encryption function using the previously defined mod_exp
pub fn rsa_encrypt<K, T>(key: &K, m: T) -> T
where
    K: PublicKeyParts<T>,                     // Public key trait with generic type T
    T: PrimInt + Num + Zero + One + Unsigned, // Numeric type for the message and key components
{
    mod_exp(m, *key.e(), *key.n()) // Perform modular exponentiation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_exp() {
        let base = 2u64;
        let exp = 3u64;
        let modulus = 5u64;

        let result = mod_exp(base, exp, modulus);
        assert_eq!(result, 3);
    }
}
