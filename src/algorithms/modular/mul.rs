use num_traits::PrimInt;
use num_traits::{Unsigned, WrappingAdd, WrappingSub};

use crate::traits::UnsignedModularInt;

use super::add::mod_add;

pub fn mod_mul<T>(mut a: T, mut b: T, m: T) -> T
where
    T: UnsignedModularInt,
{
    a = a % m;
    b = b % m;

    let mut result = T::zero();

    while b > T::zero() {
        if b & T::one() == T::one() {
            result = mod_add(result, a, m);
        }

        a = mod_add(a, a, m);
        b = b >> 1;
    }

    result
}

#[cfg(test)]
mod mul_tests {
    use super::*;

    #[test]
    fn test_basic_cases() {
        assert_eq!(mod_mul(7u8, 13, 19), 15); // (7 * 13) % 19 = 15
        assert_eq!(mod_mul(6u8, 9, 7), 5); // (6 * 9) % 7 = 5
        assert_eq!(mod_mul(5u8, 5, 11), 3); // (5 * 5) % 11 = 3
    }

    #[test]
    fn test_a_is_zero() {
        assert_eq!(mod_mul(0u8, 5, 7), 0); // (0 * 5) % 7 = 0
        assert_eq!(mod_mul(0u8, 255, 19), 0); // (0 * 255) % 19 = 0
    }

    #[test]
    fn test_b_is_zero() {
        assert_eq!(mod_mul(5u8, 0, 7), 0); // (5 * 0) % 7 = 0
        assert_eq!(mod_mul(255u8, 0, 19), 0); // (255 * 0) % 19 = 0
    }

    #[test]
    fn test_modulus_is_one() {
        assert_eq!(mod_mul(7u8, 13, 1), 0); // (7 * 13) % 1 = 0
        assert_eq!(mod_mul(255u8, 255, 1), 0); // (255 * 255) % 1 = 0
    }

    #[test]
    #[should_panic]
    fn test_modulus_is_zero() {
        mod_mul(7u8, 13, 0); // Undefined behavior, expect panic or error
    }

    #[test]
    fn test_max_values() {
        assert_eq!(mod_mul(255u8, 255, 19), 7); // (255 * 255) % 19 = 7
        assert_eq!(mod_mul(255u8, 255, 255), 0); // (255 * 255) % 255 = 0
    }

    #[test]
    fn test_multiplication_by_one() {
        assert_eq!(mod_mul(1u8, 5, 7), 5 % 7); // (1 * 5) % 7 = 5
        assert_eq!(mod_mul(7u8, 1, 19), 7 % 19); // (7 * 1) % 19 = 7
    }

    #[test]
    fn test_equal_values() {
        assert_eq!(mod_mul(7u8, 7, 19), (7 * 7) % 19); // (7 * 7) % 19 = 11
        assert_eq!(mod_mul(13u8, 13, 19), (13 * 13) % 19); // (13 * 13) % 19 = 17
    }

    #[test]
    fn test_prime_moduli() {
        assert_eq!(mod_mul(7u8, 13, 19), (7 * 13) % 19); // (7 * 13) % 19 = 15
        assert_eq!(mod_mul(8u8, 9, 17), (8 * 9) % 17); // (8 * 9) % 17 = 4
        assert_eq!(mod_mul(5u8, 11, 23), (5 * 11) % 23); // (5 * 11) % 23 = 9
    }

    #[test]
    fn test_large_values_small_modulus() {
        assert_eq!(mod_mul(200u8, 200, 7), 2); // (200 * 200) % 7 = 2
        assert_eq!(mod_mul(255u8, 255, 3), 0); // (255 * 255) % 3 = 0
    }

    #[test]
    fn test_small_modulus() {
        assert_eq!(mod_mul(7u8, 8, 2), (7 * 8) % 2); // (7 * 8) % 2 = 0
        assert_eq!(mod_mul(5u8, 6, 4), (5 * 6) % 4); // (5 * 6) % 4 = 2
    }

    #[test]
    fn test_powers_of_two_modulus() {
        assert_eq!(mod_mul(7u8, 13, 8), 3); // (7 * 13) % 8 = 3
        assert_eq!(mod_mul(16u8, 16, 16), 0); // (16 * 16) % 16 = 0
    }

    #[test]
    fn test_modulus_greater_than_a_or_b() {
        assert_eq!(mod_mul(10u8, 12, 20), (10 * 12) % 20); // (10 * 12) % 20 = 0
        assert_eq!(mod_mul(15u8, 14, 30), (15 * 14) % 30); // (15 * 14) % 30 = 0
    }

    #[test]
    fn test_a_or_b_equals_m_minus_1() {
        assert_eq!(mod_mul(18u8, 13, 19), (18 * 13) % 19); // (18 * 13) % 19 = 6
        assert_eq!(mod_mul(7u8, 16, 17), (7 * 16) % 17); // (7 * 16) % 17 = 10
    }

    #[test]
    fn test_binary_modulus() {
        assert_eq!(mod_mul(5u8, 6, 2), (5 * 6) % 2); // (5 * 6) % 2 = 0
    }

    #[test]
    fn test_small_moduli_explicit() {
        assert_eq!(mod_mul(10u8, 9, 2), (10 * 9) % 2); // (10 * 9) % 2 = 0
        assert_eq!(mod_mul(10u8, 9, 3), (10 * 9) % 3); // (10 * 9) % 3 = 0
    }

    #[test]
    fn test_a_and_b_equals_m_minus_1() {
        assert_eq!(mod_mul(18u8, 18, 19), 1); // (18 * 18) % 19 = 1
        assert_eq!(mod_mul(254u8, 254, 255), 1); // (254 * 254) % 255 = 1
    }

    #[test]
    fn test_a_or_b_equals_modulus() {
        assert_eq!(mod_mul(7u8, 8, 8), 0); // (7 * 8) % 8 = 0
        assert_eq!(mod_mul(8u8, 8, 8), 0); // (8 * 8) % 8 = 0
    }

    #[test]
    fn test_large_product_small_modulus() {
        assert_eq!(mod_mul(250u8, 240, 13), 5); // (250 * 240) % 13 = 5
        assert_eq!(mod_mul(200u8, 200, 5), 0); // (200 * 200) % 5 = 0
    }

    #[test]
    fn test_64bit_large_values() {
        // Maximum possible u64 values
        assert_eq!(mod_mul(u64::MAX, u64::MAX, u64::MAX), 0); // (MAX * MAX) % MAX = 0

        // Large prime modulus and values close to MAX
        assert_eq!(
            mod_mul(u64::MAX, u64::MAX - 1, 1_000_000_007_u64),
            532600269
        );

        // Case where a and b multiply to a value larger than 64-bit but mod reduces
        assert_eq!(
            mod_mul(
                12345678901234567890_u64,
                9876543210987654321_u64,
                1_000_000_007_u64
            ),
            77470638
        );

        // Edge case: modulus just above a and b
        assert_eq!(mod_mul(10_u64, 20_u64, u64::MAX), (10 * 20) % u64::MAX);
    }

    #[test]
    fn test_64bit_overflows() {
        // Overflow scenario for smaller types but correct for u64
        assert_eq!(mod_mul(2_u64.pow(32), 2_u64.pow(32), u64::MAX), 1);
    }

    #[test]
    fn test_64bit_specific_patterns() {
        // Test with powers of two
        assert_eq!(mod_mul(2_u64.pow(63), 2, u64::MAX), 1);

        // Near max and near zero modulus
        assert_eq!(
            mod_mul(u64::MAX - 1, 1, u64::MAX),
            (u64::MAX - 1) % u64::MAX
        ); // Just below MAX

        // Prime modulus large values
        let large_prime = 18_446_744_073_709_551_557_u64; // Largest 64-bit prime

        assert_eq!(mod_mul(u64::MAX, u64::MAX - 1, large_prime), 3306_u64);

        // Stress with small modulus and large values
        assert_eq!(mod_mul(u64::MAX - 1, u64::MAX - 1, 2_u64), 0);
    }
}
