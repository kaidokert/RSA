use crate::traits::UnsignedModularInt;

pub fn mod_add<T>(a: T, b: T, m: T) -> T
where
    T: UnsignedModularInt,
{
    let a_mod = a % m;
    let b_mod = b % m;
    let sum = a_mod.wrapping_add(&b_mod);

    if sum >= m || sum < a_mod {
        // Use wrapping_sub to handle potential underflow
        sum.wrapping_sub(&m)
    } else {
        sum
    }
}

#[cfg(test)]
mod add_tests {
    use super::*;

    // Test cases for mod_add function
    #[test]
    fn test_mod_add_basic() {
        // Basic addition without overflow and sum less than modulus
        assert_eq!(mod_add(5u8, 10u8, 20u8), 15u8); // 5 + 10 = 15 < 20
        assert_eq!(mod_add(7u8, 6u8, 14u8), 13u8); // 7 + 6 = 13 < 14
        assert_eq!(mod_add(0u8, 0u8, 10u8), 0u8); // 0 + 0 = 0
    }

    #[test]
    fn test_mod_add_sum_equals_modulus() {
        // Sum equals modulus, result should be 0
        assert_eq!(mod_add(10u8, 10u8, 20u8), 0u8); // 10 + 10 = 20 % 20 = 0
        assert_eq!(mod_add(15u8, 5u8, 20u8), 0u8); // 15 + 5 = 20 % 20 = 0
    }

    #[test]
    fn test_mod_add_sum_exceeds_modulus() {
        // Sum exceeds modulus but no overflow occurs
        assert_eq!(mod_add(15u8, 10u8, 20u8), 5u8); // (15 + 10) % 20 = 25 % 20 = 5
        assert_eq!(mod_add(25u8, 10u8, 30u8), 5u8); // (25 + 10) % 30 = 35 % 30 = 5
    }

    #[test]
    fn test_mod_add_overflow() {
        // Addition causes overflow, sum exceeds u8::MAX
        assert_eq!(mod_add(200u8, 100u8, 50u8), 0u8); // (200 + 100) % 50 = 44 % 50 = 44
        assert_eq!(mod_add(255u8, 255u8, 100u8), 10u8); // Overflow occurs
    }

    #[test]
    fn test_mod_add_with_zero() {
        // One or both operands are zero
        assert_eq!(mod_add(0u8, 25u8, 30u8), 25u8); // 0 + 25 = 25
        assert_eq!(mod_add(25u8, 0u8, 30u8), 25u8); // 25 + 0 = 25
        assert_eq!(mod_add(0u8, 0u8, 30u8), 0u8); // 0 + 0 = 0
    }

    #[test]
    fn test_mod_add_with_max_values() {
        // Operands are at or near u8::MAX
        assert_eq!(mod_add(255u8, 1u8, 100u8), 56u8); // Overflow occurs
        assert_eq!(mod_add(254u8, 1u8, 255u8), 0u8); // 254 + 1 = 255 % 255 = 0
        assert_eq!(mod_add(255u8, 255u8, 255u8), 0u8); // Overflow, result should be 0
    }

    #[test]
    fn test_mod_add_modulus_is_one() {
        // Modulus is one, result should always be 0
        assert_eq!(mod_add(10u8, 20u8, 1u8), 0u8);
        assert_eq!(mod_add(255u8, 255u8, 1u8), 0u8);
    }

    #[test]
    #[should_panic]
    fn test_mod_add_modulus_is_zero() {
        // Modulus is zero, should panic or handle error
        mod_add(10u8, 20u8, 0u8);
    }

    #[test]
    fn test_mod_add_operands_equal_modulus_minus_one() {
        // Operands equal to modulus minus one
        assert_eq!(mod_add(19u8, 19u8, 20u8), 18u8); // 19 + 19 = 38 % 20 = 18
        assert_eq!(mod_add(254u8, 254u8, 255u8), 253u8); // 254 + 254 = 508 % 255 = 253
    }

    #[test]
    fn test_mod_add_large_modulus() {
        // Modulus larger than u8::MAX, wrapping occurs
        let large_modulus = 300u16; // Use u16 to represent modulus larger than u8::MAX
        let result = mod_add(200u8, 100u8, large_modulus as u8);
        assert_eq!(result, 36u8); // (200 + 100) % 44 = 0 (since 300 % 256 = 44)
    }

    #[test]
    fn test_mod_add_modulus_equals_u8_max() {
        // Modulus equals u8::MAX
        assert_eq!(mod_add(100u8, 155u8, 255u8), 0u8); // 100 + 155 = 255 % 255 = 0
        assert_eq!(mod_add(200u8, 100u8, 255u8), 45u8); // 200 + 100 = 300 % 255 = 45
    }

    #[test]
    fn test_mod_add_overflow_edge_case() {
        // Edge case where sum wraps around due to overflow
        assert_eq!(mod_add(255u8, 1u8, 255u8), 1u8); // 255 + 1 = 0 (overflow), 0 % 255 = 0
    }

    #[test]
    fn test_mod_add_with_operands_exceeding_modulus() {
        // Operands exceed modulus
        assert_eq!(mod_add(200u8, 100u8, 50u8), 0u8); // (200 % 50) + (100 % 50) = 0 + 0 = 0
        assert_eq!(mod_add(75u8, 80u8, 60u8), 35u8); // (75 % 60) + (80 % 60) = 15 + 20 = 35
    }

    #[test]
    fn test_mod_add_with_modulus_exceeding_u8_max() {
        // Modulus exceeds u8::MAX (handled via wrapping)
        let modulus = 300u16; // Modulus exceeds u8::MAX
        let result = mod_add(250u8, 10u8, modulus as u8);
        assert_eq!(result, 40u8); // 250 + 10 = 260 % 44 = 4 (since 300 % 256 = 44)
    }
}
