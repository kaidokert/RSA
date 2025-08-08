/// # Modular Addition (Basic)
/// Simple version that operates on values and copies them. Requires
/// `WrappingAdd` and `WrappingSub` traits to be implemented.
pub fn basic_mod_add<T>(a: T, b: T, m: T) -> T
where
    T: core::cmp::PartialOrd
        + Copy
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub
        + core::ops::Rem<Output = T>,
{
    let a = a % m;
    let sum = a.wrapping_add(&(b % m));
    if sum >= m || sum < a {
        sum.wrapping_sub(&m)
    } else {
        sum
    }
}

/// # Modular Addition (Constrained)
/// Version that works with references, requires `WrappingAdd` and
/// `WrappingSub` traits to be implemented.
pub fn constrained_mod_add<T>(a: T, b: &T, m: &T) -> T
where
    T: core::cmp::PartialOrd
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>,
{
    // maybe a should be `mut a`
    let a_mod = &a % m;
    let sum = a_mod.wrapping_add(&(b % m));
    if &sum >= m || sum < a_mod {
        sum.wrapping_sub(m)
    } else {
        sum
    }
}

/// # Modular Addition (Strict)
/// Most constrained version that works with references. Requires
/// `OverflowingAdd` and `OverflowingSub` traits to be implemented.
pub fn strict_mod_add<T>(mut a: T, b: &T, m: &T) -> T
where
    T: core::cmp::PartialOrd
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub,
    for<'b> T: core::ops::RemAssign<&'b T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>,
{
    a.rem_assign(m);
    let (sum, overflow) = a.overflowing_add(&(b % m));

    if &sum >= m || overflow {
        sum.overflowing_sub(m).0
    } else {
        sum
    }
}

#[cfg(test)]
macro_rules! select_mod_add {
    ($mod_add:path, $t:ty, by_ref) => {
        fn mod_add(a: $t, b: &$t, m: &$t) -> $t {
            $mod_add(a, b, m)
        }
    };
    ($mod_add:path, $t:ty, by_val) => {
        fn mod_add(a: $t, b: &$t, m: &$t) -> $t {
            $mod_add(a, *b, *m)
        }
    };
}

#[cfg(test)]
macro_rules! generate_mod_add_tests {
    ($mod_add:path, $t:ty, $by_ref:tt) => {
        select_mod_add!($mod_add, $t, $by_ref);

        #[test]
        fn test_mod_add_basic() {
            assert_eq!(mod_add(5u8, &10u8, &20u8), 15u8);
            assert_eq!(mod_add(7u8, &6u8, &14u8), 13u8);
            assert_eq!(mod_add(0u8, &0u8, &10u8), 0u8);
        }

        #[test]
        fn test_mod_add_sum_equals_modulus() {
            assert_eq!(mod_add(10u8, &10u8, &20u8), 0u8);
            assert_eq!(mod_add(15u8, &5u8, &20u8), 0u8);
        }

        #[test]
        fn test_mod_add_sum_exceeds_modulus() {
            assert_eq!(mod_add(15u8, &10u8, &20u8), 5u8);
            assert_eq!(mod_add(25u8, &10u8, &30u8), 5u8);
        }

        #[test]
        fn test_mod_add_overflow() {
            assert_eq!(mod_add(200u8, &100u8, &50u8), 0u8);
            assert_eq!(mod_add(255u8, &255u8, &100u8), 10u8);
        }

        #[test]
        fn test_mod_add_with_zero() {
            assert_eq!(mod_add(0u8, &25u8, &30u8), 25u8);
            assert_eq!(mod_add(25u8, &0u8, &30u8), 25u8);
            assert_eq!(mod_add(0u8, &0u8, &30u8), 0u8);
        }

        #[test]
        fn test_mod_add_with_max_values() {
            assert_eq!(mod_add(255u8, &1u8, &100u8), 56u8);
            assert_eq!(mod_add(254u8, &1u8, &255u8), 0u8);
            assert_eq!(mod_add(255u8, &255u8, &255u8), 0u8);
        }

        #[test]
        fn test_mod_add_modulus_is_one() {
            assert_eq!(mod_add(10u8, &20u8, &1u8), 0u8);
            assert_eq!(mod_add(255u8, &255u8, &1u8), 0u8);
        }

        #[test]
        #[should_panic]
        fn test_mod_add_modulus_is_zero() {
            mod_add(10u8, &20u8, &0u8);
        }

        #[test]
        fn test_mod_add_operands_equal_modulus_minus_one() {
            assert_eq!(mod_add(19u8, &19u8, &20u8), 18u8);
            assert_eq!(mod_add(254u8, &254u8, &255u8), 253u8);
        }

        #[test]
        fn test_mod_add_large_modulus() {
            let large_modulus = 300u16;
            let result = mod_add(200u8, &100u8, &(large_modulus as u8));
            assert_eq!(result, 36u8);
        }

        #[test]
        fn test_mod_add_modulus_equals_u8_max() {
            assert_eq!(mod_add(100u8, &155u8, &255u8), 0u8);
            assert_eq!(mod_add(200u8, &100u8, &255u8), 45u8);
        }

        #[test]
        fn test_mod_add_overflow_edge_case() {
            assert_eq!(mod_add(255u8, &1u8, &255u8), 1u8);
        }

        #[test]
        fn test_mod_add_with_operands_exceeding_modulus() {
            assert_eq!(mod_add(200u8, &100u8, &50u8), 0u8);
            assert_eq!(mod_add(75u8, &80u8, &60u8), 35u8);
        }

        #[test]
        fn test_mod_add_with_modulus_exceeding_u8_max() {
            let modulus = 300u16;
            let result = mod_add(250u8, &10u8, &(modulus as u8));
            assert_eq!(result, 40u8);
        }
    };
}

#[cfg(test)]
mod strict_mod_add_tests {
    use super::strict_mod_add;
    generate_mod_add_tests!(strict_mod_add, u8, by_ref);
}

#[cfg(test)]
mod constrained_mod_add_tests {
    use super::constrained_mod_add;
    generate_mod_add_tests!(constrained_mod_add, u8, by_ref);
}

#[cfg(test)]
mod basic_mod_add_tests {
    use super::basic_mod_add;
    generate_mod_add_tests!(basic_mod_add, u8, by_val);
}

#[cfg(test)]
macro_rules! add_test_module {
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
                fn test_mod_add_basic() {
                    let a = U256::from(5u8);
                    let b = U256::from(10u8);
                    let m = U256::from(20u8);
                    let result = U256::from(15u8);

                    crate::maybe_test!($strict, assert_eq!(super::strict_mod_add(a, &b, &m), result));
                    let a = U256::from(5u8);
                    crate::maybe_test!($constrained, assert_eq!(super::constrained_mod_add(a, &b, &m), result));
                    let a = U256::from(5u8);
                    crate::maybe_test!($basic, assert_eq!(super::basic_mod_add(a, b, m), result));
                }
            }
        }
    };
}

#[cfg(test)]
mod bnum_add_tests {
    use super::basic_mod_add;
    use super::constrained_mod_add;
    use super::strict_mod_add;

    add_test_module!(
        bnum,
        bnum::types::U256,
        strict: off, // OverflowingAdd + OverflowingSub is not implemented
        constrained: on,
        basic: on,
    );

    add_test_module!(
        bnum_patched,
        bnum_patched::types::U256,
        strict: on,
        constrained: on,
        basic: on,
    );

    add_test_module!(
        crypto_bigint,
        crypto_bigint::U256,
        strict: off,  // "Missing OverflowingAdd + OverflowingSub" },
        constrained: off, // "Rem<'a> is not implemented for U256" },
        basic: on,
    );

    add_test_module!(
        crypto_bigint_patched,
        crypto_bigint_patched::U256,
        strict: on,
        constrained: on,
        basic: on,
    );

    add_test_module!(
        num_bigint,
        num_bigint::BigUint,
        type U256 = num_bigint::BigUint;
        strict: off, // OverflowingAdd + OverflowingSub is not implemented
        constrained: off, // WrappingAdd + WrappingSub is not implemented
        basic: off, // Copy cannot be implemented, heap allocation
    );

    add_test_module!(
        num_bigint_patched,
        num_bigint_patched::BigUint,
        type U256 = num_bigint_patched::BigUint;
        strict: on,
        constrained: on,
        basic: off, // Copy cannot be implemented, heap allocation
    );

    add_test_module!(
        ibig,
        ibig::UBig,
        type U256 = ibig::UBig;
        strict: off, // OverflowingAdd + OverflowingSub is not implemented
        constrained: off, // WrappingAdd + WrappingSub is not implemented
        basic: off, // Copy cannot be implemented, heap allocation
    );

    add_test_module!(
        ibig_patched,
        ibig_patched::UBig,
        type U256 = ibig_patched::UBig;
        strict: on,
        constrained: on,
        basic: off, // Copy cannot be implemented, heap allocation
    );

    add_test_module!(
        fixed_bigint,
        fixed_bigint::FixedUInt,
        type U256 = FixedUInt<u32, 4>;
        strict: on,
        constrained: on,
        basic: on,
    );
}
