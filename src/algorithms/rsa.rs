use num_traits::{PrimInt, Unsigned, WrappingAdd, WrappingSub};

use crate::traits::PublicKeyParts;

mod modmul;
use modmul::mod_mul;

pub fn mod_exp<T>(mut base: T, exponent: T, modulus: T) -> T
where
    T: PrimInt + Unsigned + WrappingAdd + WrappingSub,
{
    let two = T::one() + T::one();
    let mut result = T::one();
    base = base % modulus; // Reduce base initially
    let mut exp = exponent;

    while exp > T::zero() {
        // If the exponent is odd, multiply the result by base
        if exp % two == T::one() {
            result = mod_mul(result, base, modulus);
        }

        // Right shift the exponent (divide by 2)
        exp = exp / two;

        // Only square base if exp > 0 (avoid unnecessary squaring in final step)
        if exp > T::zero() {
            base = mod_mul(base, base, modulus); // Square the base using modular multiplication
        }
    }
    result
}

// Generic RSA encryption function using the previously defined mod_exp
pub fn rsa_encrypt<K, T>(key: &K, m: T) -> T
where
    K: PublicKeyParts<T>, // Public key trait with generic type T
    T: PrimInt + WrappingAdd + WrappingSub + Unsigned,
{
    mod_exp(m, *key.e(), *key.n()) // Perform modular exponentiation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_small_values() {
        assert_eq!(mod_exp(2_u64, 3_u64, 5_u64), 3_u64); // 2^3 % 5 = 8 % 5 = 3
        assert_eq!(mod_exp(5_u64, 0_u64, 7_u64), 1_u64); // 5^0 % 7 = 1
    }

    #[test]
    fn test_basic_base_or_exponent_1() {
        assert_eq!(mod_exp(1_u64, 10_u64, 7_u64), 1_u64); // 1^10 % 7 = 1
        assert_eq!(mod_exp(7_u64, 1_u64, 13_u64), 7_u64); // 7^1 % 13 = 7
    }

    #[test]
    fn test_identity_modulus_of_1() {
        assert_eq!(mod_exp(10_u64, 10_u64, 1_u64), 0_u64); // Any number % 1 = 0
    }

    #[test]
    fn test_identity_exponent_of_0() {
        assert_eq!(mod_exp(5_u64, 0_u64, 9_u64), 1_u64); // 5^0 % 9 = 1
    }

    #[test]
    fn test_identity_zero_to_the_zero() {
        // Handle 0^0 case based on how it's defined in your mod_exp implementation.
        assert_eq!(mod_exp(0_u64, 0_u64, 7_u64), 1_u64); // This assumes 0^0 = 1
    }

    #[test]
    fn test_edge_max_u8_values() {
        // Equivalent of mod_exp(u64::MAX, 2_u64, u64::MAX) with u8
        assert_eq!(mod_exp(u8::MAX, 2_u8, u8::MAX), 0_u8); // (255^2) % 255 = 0
        assert_eq!(mod_exp(u8::MAX, 2_u8, 97_u8), 35_u8); // (255^2) % 97 = 35
    }

    #[test]
    fn test_big_exponent_mod_u8() {
        assert_eq!(mod_exp(u8::MAX, 2_u8, 97_u8), 35_u8); // (255^2) % 97 = 35
    }

    #[test]
    fn test_edge_max_u16_values() {
        // Equivalent of mod_exp(u64::MAX, 2_u64, u64::MAX) with u16
        assert_eq!(mod_exp(u16::MAX, 2_u16, u16::MAX), 0_u16); // (65535^2) % 65535 = 0
    }

    #[test]
    fn test_edge_max_u32_values() {
        // Equivalent of mod_exp(u64::MAX, 2_u64, u64::MAX) with u32
        assert_eq!(mod_exp(u32::MAX, 2_u32, u32::MAX), 0_u32); // (4294967295^2) % 4294967295 = 0
    }

    #[test]
    fn test_edge_max_u64_values() {
        assert_eq!(mod_exp(u64::MAX, 2_u64, u64::MAX), 0_u64); // (2^63 - 1)^2 % (2^63 - 1) = 0
        assert_eq!(mod_exp(u64::MAX, 2_u64, 1_000_000_007_u64), 114_944_269_u64);
        // Big exponent mod test
    }

    #[test]
    fn test_edge_base_of_zero() {
        assert_eq!(mod_exp(0_u64, 10_u64, 7_u64), 0_u64); // 0^10 % 7 = 0
    }

    #[test]
    fn test_prime_modulus() {
        assert_eq!(mod_exp(7_u64, 13_u64, 19_u64), 7_u64); // 7^13 % 19 = 7
        assert_eq!(mod_exp(3_u64, 13_u64, 17_u64), 12_u64); // 3^13 % 17 = 12
    }

    #[test]
    fn test_large_exponent() {
        // This test assumes efficient modular exponentiation like exponentiation by squaring.
        assert_eq!(mod_exp(7_u64, 1 << 20, 13_u64), 9_u64); // 7^2^20 % 13 = 9
    }

    #[test]
    fn test_overflow_handling_u8() {
        // Equivalent of mod_exp(2^32, 2^32, 97) with u8
        assert_eq!(mod_exp(2_u8.pow(4), 2_u8.pow(4), 97_u8), 61_u8); // (16^16) % 97 = 61
    }

    #[test]
    fn test_overflow_handling() {
        assert_eq!(mod_exp(2_u64.pow(32), 2_u64.pow(32), 97_u64), 35_u64); // Big exponent/modulus
        assert_eq!(
            mod_exp(2_u64.pow(63), 2_u64.pow(63), 1_000_000_007_u64),
            719_537_220_u64
        );
    }

    #[test]
    fn test_prime_modulus_u8() {
        // Equivalent of mod_exp(7_u64, 13_u64, 19_u64) with u8
        assert_eq!(mod_exp(7_u8, 13_u8, 19_u8), 7_u8); // 7^13 % 19 = 7
    }

    #[test]
    fn test_coprime_values() {
        assert_eq!(
            mod_exp(123_456_789_u64, 987_654_321_u64, 1_000_000_007_u64),
            652_541_198_u64
        );
    }
}
