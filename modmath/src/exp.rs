use super::mul::{basic_mod_mul, constrained_mod_mul, strict_mod_mul};

/// # Modular Exponentiation (Basic)
/// Simple version that operates on values and copies them. Requires
/// `WrappingAdd` and `WrappingSub` traits to be implemented.
pub fn basic_mod_exp<T>(mut base: T, exponent: T, modulus: T) -> T
where
    T: PartialOrd
        + num_traits::One
        + num_traits::Zero
        + core::ops::BitAnd<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::Shr<usize, Output = T>
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub
        + core::ops::ShrAssign<usize>
        + core::ops::RemAssign<T>
        + Copy,
{
    let two = T::one() + T::one();
    let mut result = T::one();
    let mut exp = exponent;

    base %= modulus; // reduce base initially

    while exp > T::zero() {
        // If the exponent is odd, multiply the result by base
        if exp % two == T::one() {
            result = basic_mod_mul(result, base, modulus);
        }
        // Right shift the exponent (divide by 2)
        exp >>= 1;

        // Only square base if exp > 0 (avoid unnecessary squaring in final step)
        if exp > T::zero() {
            // Square the base using modular multiplication
            base = basic_mod_mul(base, base, modulus);
        }
    }
    result
}

/// # Modular Exponentiation (Constrained)
/// Version that works with references, requires `WrappingAdd` and
/// `WrappingSub` traits to be implemented.
pub fn constrained_mod_exp<T>(mut base: T, exponent: &T, modulus: &T) -> T
where
    T: PartialOrd
        + num_traits::One
        + num_traits::Zero
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub
        + core::ops::ShrAssign<usize>
        + core::ops::Shr<usize, Output = T>,
    for<'a> T: core::ops::RemAssign<&'a T>
        + core::ops::DivAssign<&'a T>
        + core::ops::Rem<&'a T, Output = T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T> + core::ops::BitAnd<Output = T>,
{
    base.rem_assign(modulus);
    let mut result = T::one();
    let mut exp = T::zero().wrapping_add(exponent);
    let two = T::one().wrapping_add(&T::one());
    while exp > T::zero() {
        if &exp % &two == T::one() {
            result = constrained_mod_mul(result, &base, modulus);
        }
        exp >>= 1;
        if exp > T::zero() {
            let tmp_base = T::zero().wrapping_add(&base);
            base = constrained_mod_mul(base, &tmp_base, modulus);
        }
    }
    result
}

/// # Modular Exponentiation (Strict)
/// Most constrained version that works with references. Requires
/// `OverflowingAdd` and `OverflowingSub` traits to be implemented, and
/// all multiplication contraints as well.
pub fn strict_mod_exp<T>(mut base: T, exponent: &T, modulus: &T) -> T
where
    T: PartialOrd
        + num_traits::One
        + num_traits::Zero
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub
        + core::ops::Shr<usize, Output = T>,
    for<'a> T: core::ops::RemAssign<&'a T>
        + core::ops::DivAssign<&'a T>
        + core::ops::ShrAssign<usize>
        + core::ops::Rem<&'a T, Output = T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T> + core::ops::BitAnd<Output = T>,
{
    let two = T::one().overflowing_add(&T::one()).0;
    let mut result = T::one();
    base.rem_assign(modulus);
    let mut exp = T::zero().overflowing_add(exponent).0;

    while exp > T::zero() {
        if &exp % &two == T::one() {
            result = strict_mod_mul(result, &base, modulus);
        }
        exp >>= 1;

        if exp > T::zero() {
            let tmp_base = T::zero().overflowing_add(&base).0;
            base = strict_mod_mul(base, &tmp_base, modulus);
        }
    }
    result
}

#[cfg(test)]
macro_rules! select_mod_exp {
    ($mod_exp:path, $t:ty, by_ref) => {
        fn mod_exp(a: $t, b: &$t, m: &$t) -> $t {
            $mod_exp(a, b, m)
        }
    };
    ($mod_exp:path, $t:ty, by_val) => {
        fn mod_exp(a: $t, b: &$t, m: &$t) -> $t {
            $mod_exp(a, *b, *m)
        }
    };
}

#[cfg(test)]
macro_rules! generate_mod_exp_tests_block_64 {
    ($mod_add:path, $t:ty, $by_ref:tt) => {
        select_mod_exp!($mod_add, $t, $by_ref);

        #[test]
        fn test_basic_small_values() {
            assert_eq!(mod_exp(2_u64, &3_u64, &5_u64), 3_u64); // 2^3 % 5 = 8 % 5 = 3
            assert_eq!(mod_exp(5_u64, &0_u64, &7_u64), 1_u64); // 5^0 % 7 = 1
        }

        #[test]
        fn test_basic_base_or_exponent_1() {
            assert_eq!(mod_exp(1_u64, &10_u64, &7_u64), 1_u64); // 1^10 % 7 = 1
            assert_eq!(mod_exp(7_u64, &1_u64, &13_u64), 7_u64); // 7^1 % 13 = 7
        }

        #[test]
        fn test_identity_modulus_of_1() {
            assert_eq!(mod_exp(10_u64, &10_u64, &1_u64), 0_u64); // Any number % 1 = 0
        }

        #[test]
        fn test_identity_exponent_of_0() {
            assert_eq!(mod_exp(5_u64, &0_u64, &9_u64), 1_u64); // 5^0 % 9 = 1
        }

        #[test]
        fn test_identity_zero_to_the_zero() {
            // Handle 0^0 case based on how it's defined in your mod_exp implementation.
            assert_eq!(mod_exp(0_u64, &0_u64, &7_u64), 1_u64); // This assumes 0^0 = 1
        }

        #[test]
        fn test_edge_max_u64_values() {
            assert_eq!(mod_exp(u64::MAX, &2_u64, &u64::MAX), 0_u64); // (2^63 - 1)^2 % (2^63 - 1) = 0
            assert_eq!(
                mod_exp(u64::MAX, &2_u64, &1_000_000_007_u64),
                114_944_269_u64
            );
            // Big exponent mod test
        }

        #[test]
        fn test_edge_base_of_zero() {
            assert_eq!(mod_exp(0_u64, &10_u64, &7_u64), 0_u64); // 0^10 % 7 = 0
        }

        #[test]
        fn test_prime_modulus() {
            assert_eq!(mod_exp(7_u64, &13_u64, &19_u64), 7_u64); // 7^13 % 19 = 7
            assert_eq!(mod_exp(3_u64, &13_u64, &17_u64), 12_u64); // 3^13 % 17 = 12
        }

        #[test]
        fn test_large_exponent() {
            // This test assumes efficient modular exponentiation like exponentiation by squaring.
            assert_eq!(mod_exp(7_u64, &(1 << 20), &13_u64), 9_u64); // 7^2^20 % 13 = 9
        }

        #[test]
        fn test_overflow_handling() {
            assert_eq!(mod_exp(2_u64.pow(32), &2_u64.pow(32), &97_u64), 35_u64); // Big exponent/modulus
            assert_eq!(
                mod_exp(2_u64.pow(63), &2_u64.pow(63), &1_000_000_007_u64),
                719_537_220_u64
            );
        }

        #[test]
        fn test_coprime_values() {
            assert_eq!(
                mod_exp(123_456_789_u64, &987_654_321_u64, &1_000_000_007_u64),
                652_541_198_u64
            );
        }
    };
}

#[cfg(test)]
macro_rules! generate_mod_exp_tests_block_8 {
    ($mod_add:path, $t:ty, $by_ref:tt) => {
        select_mod_exp!($mod_add, $t, $by_ref);

        #[test]
        fn test_edge_max_u8_values() {
            // Equivalent of mod_exp(u64::MAX, 2_u64, u64::MAX) with u8
            assert_eq!(mod_exp(u8::MAX, &2_u8, &u8::MAX), 0_u8); // (255^2) % 255 = 0
            assert_eq!(mod_exp(u8::MAX, &2_u8, &97_u8), 35_u8); // (255^2) % 97 = 35
        }

        #[test]
        fn test_big_exponent_mod_u8() {
            assert_eq!(mod_exp(u8::MAX, &2_u8, &97_u8), 35_u8); // (255^2) % 97 = 35
        }

        #[test]
        fn test_overflow_handling_u8() {
            // Equivalent of mod_exp(2^32, 2^32, 97) with u8
            assert_eq!(mod_exp(2_u8.pow(4), &2_u8.pow(4), &97_u8), 61_u8); // (16^16) % 97 = 61
        }

        #[test]
        fn test_prime_modulus_u8() {
            // Equivalent of mod_exp(7_u64, 13_u64, 19_u64) with u8
            assert_eq!(mod_exp(7_u8, &13_u8, &19_u8), 7_u8); // 7^13 % 19 = 7
        }
    };
}
#[cfg(test)]
macro_rules! generate_mod_exp_tests_block_16 {
    ($mod_add:path, $t:ty, $by_ref:tt) => {
        select_mod_exp!($mod_add, $t, $by_ref);

        #[test]
        fn test_edge_max_u16_values() {
            // Equivalent of mod_exp(u64::MAX, 2_u64, u64::MAX) with u16
            assert_eq!(mod_exp(u16::MAX, &2_u16, &u16::MAX), 0_u16); // (65535^2) % 65535 = 0
        }
    };
}

#[cfg(test)]
macro_rules! generate_mod_exp_tests_block_32 {
    ($mod_add:path, $t:ty, $by_ref:tt) => {
        select_mod_exp!($mod_add, $t, $by_ref);

        #[test]
        fn test_edge_max_u32_values() {
            // Equivalent of mod_exp(u64::MAX, 2_u64, u64::MAX) with u32
            assert_eq!(mod_exp(u32::MAX, &2_u32, &u32::MAX), 0_u32); // (4294967295^2) % 4294967295 = 0
        }
    };
}

#[cfg(test)]
mod strict_mod_exp_tests {
    use super::strict_mod_exp;
    mod u64_tests {
        generate_mod_exp_tests_block_64!(super::strict_mod_exp, u64, by_ref);
    }
    mod u8_tests {
        generate_mod_exp_tests_block_8!(super::strict_mod_exp, u8, by_ref);
    }
    mod u16_tests {
        generate_mod_exp_tests_block_16!(super::strict_mod_exp, u16, by_ref);
    }
    mod u32_tests {
        generate_mod_exp_tests_block_32!(super::strict_mod_exp, u32, by_ref);
    }
}

#[cfg(test)]
mod constrained_mod_exp_tests {
    use super::constrained_mod_exp;

    mod u64_tests {
        generate_mod_exp_tests_block_64!(super::constrained_mod_exp, u64, by_ref);
    }
    mod u8_tests {
        generate_mod_exp_tests_block_8!(super::constrained_mod_exp, u8, by_ref);
    }
    mod u16_tests {
        generate_mod_exp_tests_block_16!(super::constrained_mod_exp, u16, by_ref);
    }
    mod u32_tests {
        generate_mod_exp_tests_block_32!(super::constrained_mod_exp, u32, by_ref);
    }
}

#[cfg(test)]
mod basic_mod_exp_tests {
    use super::basic_mod_exp;

    mod u64_tests {
        generate_mod_exp_tests_block_64!(super::basic_mod_exp, u64, by_val);
    }
    mod u8_tests {
        generate_mod_exp_tests_block_8!(super::basic_mod_exp, u8, by_val);
    }
    mod u16_tests {
        generate_mod_exp_tests_block_16!(super::basic_mod_exp, u16, by_val);
    }
    mod u32_tests {
        generate_mod_exp_tests_block_32!(super::basic_mod_exp, u32, by_val);
    }
}

#[cfg(test)]
macro_rules! exp_test_module {
    (
        $stem:ident,           // Base name (e.g., "bnum")
        $type_path:path,       // Full path to the type
        $(type $type_def:ty = $type_expr:ty;)? // Optional type definition
        strict: $strict:expr,
        constrained: $constrained:expr,
        basic: $basic:expr,
    ) => {
        paste::paste! {
            mod [<$stem _tests>] {     // This creates e.g., mod bnum_tests
                #[allow(unused_imports)]
                use $type_path;
                $( type $type_def = $type_expr; )?

                #[test]
                #[allow(unused_variables)]
                fn test_mod_exp_basic() {
                    let a = U256::from(5u8);
                    let b = U256::from(3u8);
                    let m = U256::from(13u8);

                    // pow(5,3,13)
                    let a_val = 5u8;
                    let a = U256::from(a_val);
                    let b = U256::from(3u8);
                    let m = U256::from(13u8);
                    let result = U256::from(8u8);

                    crate::maybe_test!($strict, assert_eq!(super::strict_mod_exp(a, &b, &m), result));
                    let a = U256::from(a_val);
                    crate::maybe_test!($constrained, assert_eq!(super::constrained_mod_exp(a, &b, &m), result));
                    let a = U256::from(a_val);
                    crate::maybe_test!($basic, assert_eq!(super::basic_mod_exp(a, b, m), result));

                    // pow(123,45,1000)
                    let a_val = 123u8;
                    let a = U256::from(a_val);
                    let b = U256::from(45u8);
                    let m = U256::from(1000u16);
                    let result = U256::from(43u16);

                    crate::maybe_test!($strict, assert_eq!(super::strict_mod_exp(a, &b, &m), result));
                    let a = U256::from(a_val);
                    crate::maybe_test!($constrained, assert_eq!(super::constrained_mod_exp(a, &b, &m), result));
                    let a = U256::from(a_val);
                    crate::maybe_test!($basic, assert_eq!(super::basic_mod_exp(a, b, m), result));
                }
            }
        }
    };
}

#[cfg(test)]
mod bnum_exp_tests {
    use super::basic_mod_exp;
    use super::constrained_mod_exp;
    use super::strict_mod_exp;

    exp_test_module!(
        bnum,
        bnum::types::U256,
        strict: off, // OverflowingAdd + OverflowingSub is not implemented
        constrained: on,
        basic: on,
    );

    exp_test_module!(
        bnum_patched,
        bnum_patched::types::U256,
        strict: on,
        constrained: on,
        basic: on,
    );

    exp_test_module!(
        crypto_bigint,
        crypto_bigint::U256,
        strict: off, // OverflowingAdd missing
        constrained: off, // RemAssign
        basic: off, // RemAssign is not implemented
    );

    exp_test_module!(
        crypto_bigint_patched,
        crypto_bigint_patched::U256,
        strict: on,
        constrained: on,
        basic: on,
    );

    exp_test_module!(
        num_bigint,
        num_bigint::BigUint,
        type U256 = num_bigint::BigUint;
        strict: off, // OverflowingAdd missing
        constrained: off, // WrappingAdd missing
        basic: off, // Copy cannot be implemented, heap allocation
    );

    exp_test_module!(
        num_bigint_patched,
        num_bigint_patched::BigUint,
        type U256 = num_bigint_patched::BigUint;
        strict: on,
        constrained: on,
        basic: off, // Copy cannot be implemented, heap allocation
    );

    exp_test_module!(
        ibig,
        ibig::UBig,
        type U256 = ibig::UBig;
        strict: off, // OverflowingAdd missing
        constrained: off, // WrappingAdd missing
        basic: off, // Copy cannot be implemented, heap allocation
    );

    exp_test_module!(
        ibig_patched,
        ibig_patched::UBig,
        type U256 = ibig_patched::UBig;
        strict: on,
        constrained: on,
        basic: off, // Copy cannot be implemented, heap allocation
    );

    exp_test_module!(
        fixed_bigint,
        fixed_bigint::FixedUInt,
        type U256 = fixed_bigint::FixedUInt<u8, 4>;
        strict: on,
        constrained: on,
        basic: on,
    );
}
