// Montgomery form arithmetic module
// Contains basic and strict implementations organized in submodules

pub mod basic_mont;

pub mod strict_mont;

// Re-export basic functions for backwards compatibility
pub use basic_mont::{
    basic_compute_montgomery_params, basic_compute_montgomery_params_with_method,
    basic_from_montgomery, basic_montgomery_mod_exp, basic_montgomery_mod_mul,
    basic_montgomery_mul, basic_to_montgomery, NPrimeMethod,
};

// Re-export strict functions
pub use strict_mont::{
    strict_compute_montgomery_params, strict_compute_montgomery_params_with_method,
    strict_from_montgomery, strict_montgomery_mod_exp, strict_montgomery_mod_mul,
    strict_to_montgomery,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_compute_montgomery_params() {
        // Test with our documented example: N = 13
        // Expected: R = 16, R^(-1) = 9, N' = 11, r_bits = 4
        let (r, r_inv, n_prime, r_bits) = basic_compute_montgomery_params(13u32);

        assert_eq!(r, 16);
        assert_eq!(r_inv, 9);
        assert_eq!(n_prime, 11);
        assert_eq!(r_bits, 4);

        // Verify the mathematical properties
        // 1. R * R^(-1) ≡ 1 (mod N)
        assert_eq!((r * r_inv) % 13, 1);

        // 2. N * N' ≡ -1 (mod R) which means N * N' ≡ R - 1 (mod R)
        assert_eq!((13 * n_prime) % r, r - 1);

        // 3. R should be > N and a power of 2
        assert!(r > 13);
        assert_eq!(r, 1u32 << r_bits);
    }

    #[test]
    fn test_basic_compute_montgomery_params_with_method() {
        // Test that the parametrized version produces identical results
        let default_result = basic_compute_montgomery_params(13u32);
        let explicit_trial_result =
            basic_compute_montgomery_params_with_method(13u32, NPrimeMethod::TrialSearch);

        // Both should produce identical results since TrialSearch is the default
        assert_eq!(default_result, explicit_trial_result);

        // Verify the explicit method call produces correct values
        let (r, r_inv, n_prime, r_bits) = explicit_trial_result;
        assert_eq!(r, 16);
        assert_eq!(r_inv, 9);
        assert_eq!(n_prime, 11);
        assert_eq!(r_bits, 4);
    }

    #[test]
    fn test_n_prime_method_enum() {
        // Test that the enum default is TrialSearch
        assert_eq!(NPrimeMethod::default(), NPrimeMethod::TrialSearch);
    }

    #[test]
    fn test_extended_euclidean_n_prime_method() {
        // Test Extended Euclidean method produces same results as trial search
        let trial_result =
            basic_compute_montgomery_params_with_method(13u32, NPrimeMethod::TrialSearch);
        let euclidean_result =
            basic_compute_montgomery_params_with_method(13u32, NPrimeMethod::ExtendedEuclidean);

        assert_eq!(
            trial_result, euclidean_result,
            "Extended Euclidean should produce same result as trial search"
        );

        // Verify the Extended Euclidean result is mathematically correct
        let (r, r_inv, n_prime, r_bits) = euclidean_result;
        assert_eq!(r, 16);
        assert_eq!(r_inv, 9);
        assert_eq!(n_prime, 11);
        assert_eq!(r_bits, 4);

        // Verify N * N' ≡ -1 (mod R)
        assert_eq!((13 * n_prime) % r, r - 1, "N * N' should equal R - 1 mod R");
    }

    #[test]
    fn test_extended_euclidean_with_different_moduli() {
        // Test Extended Euclidean with various moduli to ensure correctness
        let test_cases = [7u32, 11u32, 13u32, 17u32, 19u32, 23u32];

        for modulus in test_cases.iter() {
            let trial_result =
                basic_compute_montgomery_params_with_method(*modulus, NPrimeMethod::TrialSearch);
            let euclidean_result = basic_compute_montgomery_params_with_method(
                *modulus,
                NPrimeMethod::ExtendedEuclidean,
            );

            assert_eq!(
                trial_result, euclidean_result,
                "Methods should produce same result for modulus {}",
                modulus
            );

            // Verify mathematical correctness
            let (r, _r_inv, n_prime, _r_bits) = euclidean_result;
            assert_eq!(
                (*modulus * n_prime) % r,
                r - 1,
                "N * N' should equal R - 1 mod R for modulus {}",
                modulus
            );
        }
    }

    #[test]
    fn test_hensels_lifting_n_prime_method() {
        // Test Hensel's lifting method produces same results as other methods
        let trial_result =
            basic_compute_montgomery_params_with_method(13u32, NPrimeMethod::TrialSearch);
        let hensels_result =
            basic_compute_montgomery_params_with_method(13u32, NPrimeMethod::HenselsLifting);

        assert_eq!(
            trial_result, hensels_result,
            "Hensel's lifting should produce same result as trial search"
        );

        // Verify the Hensel's result is mathematically correct
        let (r, r_inv, n_prime, r_bits) = hensels_result;
        assert_eq!(r, 16);
        assert_eq!(r_inv, 9);
        assert_eq!(n_prime, 11);
        assert_eq!(r_bits, 4);

        // Verify N * N' ≡ -1 (mod R)
        assert_eq!((13 * n_prime) % r, r - 1, "N * N' should equal R - 1 mod R");
    }

    #[test]
    fn test_all_methods_consistency() {
        // Test that all three methods produce identical results
        let test_cases = [7u32, 11u32, 13u32, 17u32, 19u32, 23u32];

        for modulus in test_cases.iter() {
            let trial_result =
                basic_compute_montgomery_params_with_method(*modulus, NPrimeMethod::TrialSearch);
            let euclidean_result = basic_compute_montgomery_params_with_method(
                *modulus,
                NPrimeMethod::ExtendedEuclidean,
            );
            let hensels_result =
                basic_compute_montgomery_params_with_method(*modulus, NPrimeMethod::HenselsLifting);

            assert_eq!(
                trial_result, euclidean_result,
                "Trial and Extended Euclidean should match for modulus {}",
                modulus
            );
            assert_eq!(
                trial_result, hensels_result,
                "Trial and Hensel's should match for modulus {}",
                modulus
            );
            assert_eq!(
                euclidean_result, hensels_result,
                "Extended Euclidean and Hensel's should match for modulus {}",
                modulus
            );

            // Verify mathematical correctness for all methods
            let (r, _r_inv, n_prime, _r_bits) = trial_result;
            assert_eq!(
                (*modulus * n_prime) % r,
                r - 1,
                "N * N' should equal R - 1 mod R for modulus {}",
                modulus
            );
        }
    }

    #[test]
    fn test_basic_to_montgomery() {
        // Test with our documented example: N = 13, R = 16
        let (r, _r_inv, _n_prime, _r_bits) = basic_compute_montgomery_params(13u32);

        // From EXAMPLE1_COMPUTE_PARAM.md:
        // 7 -> Montgomery: 7 * 16 mod 13 = 112 mod 13 = 8
        // 5 -> Montgomery: 5 * 16 mod 13 = 80 mod 13 = 2
        assert_eq!(basic_to_montgomery(7u32, 13u32, r), 8u32);
        assert_eq!(basic_to_montgomery(5u32, 13u32, r), 2u32);

        // Test edge cases
        assert_eq!(basic_to_montgomery(0u32, 13u32, r), 0u32); // 0 * R mod N = 0
        assert_eq!(basic_to_montgomery(1u32, 13u32, r), 3u32); // 1 * 16 mod 13 = 3
    }

    #[test]
    fn test_basic_from_montgomery() {
        // Test with our documented example: N = 13
        let (r, _r_inv, n_prime, r_bits) = basic_compute_montgomery_params(13u32);

        // Test round-trip conversions
        // 7 -> Montgomery (8) -> back to normal form (should be 7)
        let mont_7 = basic_to_montgomery(7u32, 13u32, r);
        assert_eq!(mont_7, 8u32); // Verify Montgomery form
        assert_eq!(basic_from_montgomery(mont_7, 13u32, n_prime, r_bits), 7u32);

        // 5 -> Montgomery (2) -> back to normal form (should be 5)
        let mont_5 = basic_to_montgomery(5u32, 13u32, r);
        assert_eq!(mont_5, 2u32); // Verify Montgomery form
        assert_eq!(basic_from_montgomery(mont_5, 13u32, n_prime, r_bits), 5u32);

        // Test edge cases
        let mont_0 = basic_to_montgomery(0u32, 13u32, r);
        assert_eq!(basic_from_montgomery(mont_0, 13u32, n_prime, r_bits), 0u32);

        let mont_1 = basic_to_montgomery(1u32, 13u32, r);
        assert_eq!(basic_from_montgomery(mont_1, 13u32, n_prime, r_bits), 1u32);

        // Test all values 0..13 for round-trip
        for i in 0u32..13u32 {
            let mont = basic_to_montgomery(i, 13u32, r);
            let back = basic_from_montgomery(mont, 13u32, n_prime, r_bits);
            assert_eq!(
                back, i,
                "Round-trip failed for {}: {} -> {} -> {}",
                i, i, mont, back
            );
        }
    }

    #[test]
    fn test_basic_montgomery_mul() {
        // Test Montgomery domain multiplication with N = 13
        let (r, _r_inv, n_prime, r_bits) = basic_compute_montgomery_params(13u32);

        // Test: 7 * 5 = 35 ≡ 9 (mod 13)
        let a_mont = basic_to_montgomery(7u32, 13u32, r); // 7 -> 8 (Montgomery form)
        let b_mont = basic_to_montgomery(5u32, 13u32, r); // 5 -> 2 (Montgomery form)

        // Montgomery multiplication: (7*R) * (5*R) -> (7*5*R) mod N
        let result_mont = basic_montgomery_mul(a_mont, b_mont, 13u32, n_prime, r_bits);

        // Convert result back to normal form to verify
        let result = basic_from_montgomery(result_mont, 13u32, n_prime, r_bits);
        assert_eq!(result, 9u32); // 7 * 5 mod 13 = 35 mod 13 = 9

        // Test edge cases
        let zero_mont = basic_to_montgomery(0u32, 13u32, r);
        let any_mont = basic_to_montgomery(7u32, 13u32, r);

        let zero_result = basic_montgomery_mul(zero_mont, any_mont, 13u32, n_prime, r_bits);
        assert_eq!(
            basic_from_montgomery(zero_result, 13u32, n_prime, r_bits),
            0u32
        );

        let one_mont = basic_to_montgomery(1u32, 13u32, r);
        let one_result = basic_montgomery_mul(one_mont, any_mont, 13u32, n_prime, r_bits);
        assert_eq!(
            basic_from_montgomery(one_result, 13u32, n_prime, r_bits),
            7u32
        );
    }

    #[test]
    fn test_basic_montgomery_mod_mul_full_workflow() {
        // Test the complete Montgomery workflow end-to-end
        // This function does: compute params, convert to Montgomery, multiply, convert back

        // Test: 7 * 5 mod 13 = 9
        let result = basic_montgomery_mod_mul(7u32, 5u32, 13u32);
        assert_eq!(result, 9u32);

        // Verify against regular modular multiplication
        assert_eq!(result, crate::mul::basic_mod_mul(7u32, 5u32, 13u32));

        // Test more cases to ensure correctness
        for a in 0u32..13u32 {
            for b in 0u32..13u32 {
                let montgomery_result = basic_montgomery_mod_mul(a, b, 13u32);
                let regular_result = crate::mul::basic_mod_mul(a, b, 13u32);
                assert_eq!(
                    montgomery_result, regular_result,
                    "Montgomery vs regular mismatch: {} * {} mod 13: {} != {}",
                    a, b, montgomery_result, regular_result
                );
            }
        }
    }

    #[test]
    fn test_basic_montgomery_mod_exp() {
        // Test Montgomery-based exponentiation against regular exponentiation

        // Test: 7^5 mod 13 = 16807 mod 13 = 11
        let montgomery_result = basic_montgomery_mod_exp(7u32, 5u32, 13u32);
        let regular_result = crate::exp::basic_mod_exp(7u32, 5u32, 13u32);
        assert_eq!(montgomery_result, regular_result);
        assert_eq!(montgomery_result, 11u32);

        // Test edge cases
        assert_eq!(basic_montgomery_mod_exp(0u32, 5u32, 13u32), 0u32); // 0^5 = 0
        assert_eq!(basic_montgomery_mod_exp(7u32, 0u32, 13u32), 1u32); // 7^0 = 1
        assert_eq!(basic_montgomery_mod_exp(1u32, 100u32, 13u32), 1u32); // 1^100 = 1
        assert_eq!(basic_montgomery_mod_exp(7u32, 1u32, 13u32), 7u32); // 7^1 = 7

        // Comprehensive test: verify Montgomery exp matches regular exp for all small values
        for base in 0u32..13u32 {
            for exponent in 0u32..10u32 {
                let montgomery_result = basic_montgomery_mod_exp(base, exponent, 13u32);
                let regular_result = crate::exp::basic_mod_exp(base, exponent, 13u32);
                assert_eq!(
                    montgomery_result, regular_result,
                    "Montgomery vs regular exp mismatch: {}^{} mod 13: {} != {}",
                    base, exponent, montgomery_result, regular_result
                );
            }
        }

        // Test with larger exponents to verify efficiency benefits would apply
        assert_eq!(
            basic_montgomery_mod_exp(2u32, 100u32, 13u32),
            crate::exp::basic_mod_exp(2u32, 100u32, 13u32)
        );
        assert_eq!(
            basic_montgomery_mod_exp(3u32, 1000u32, 13u32),
            crate::exp::basic_mod_exp(3u32, 1000u32, 13u32)
        );
    }
}

#[cfg(test)]
macro_rules! montgomery_test_module {
    (
        $stem:ident,           // Base name (e.g., "bnum")
        $type_path:path,       // Full path to the type
        $(type $type_def:ty = $type_expr:ty;)? // Optional type definition
        strict: $strict:expr,
        basic: $basic:expr,
    ) => {
        paste::paste! {
            mod [<$stem _tests>] {     // This creates e.g., mod bnum_tests
                #[allow(unused_imports)]
                use $type_path;
                $( type $type_def = $type_expr; )?

                #[test]
                #[allow(unused_variables)]
                fn test_montgomery_mod_mul_basic() {
                    // Montgomery modular multiplication test
                    let a_val = 7u8;
                    let a = U256::from(a_val);
                    let b = U256::from(5u8);
                    let modulus = U256::from(13u8);
                    let expected = U256::from(9u8); // 7 * 5 mod 13 = 9

                    crate::maybe_test!($strict, {
                        let result = super::strict_mont::strict_montgomery_mod_mul(a, &b, &modulus);
                        assert_eq!(result, expected);

                        // Verify against regular modular multiplication
                        let regular_result = crate::mul::strict_mod_mul(a, &b, &modulus);
                        assert_eq!(result, regular_result);
                    });
                    let a = U256::from(a_val);
                    crate::maybe_test!($basic, {
                        let result = super::basic_montgomery_mod_mul(a, b, modulus);
                        assert_eq!(result, expected);

                        // Verify against regular modular multiplication
                        let regular_result = crate::mul::basic_mod_mul(a, b, modulus);
                        assert_eq!(result, regular_result);
                    });
                }

                #[test]
                #[allow(unused_variables)]
                fn test_montgomery_mod_exp_basic() {
                    // Montgomery modular exponentiation test
                    let base_val = 7u8;
                    let base = U256::from(base_val);
                    let exponent = U256::from(5u8);
                    let modulus = U256::from(13u8);
                    let expected = U256::from(11u8); // 7^5 mod 13 = 11

                    crate::maybe_test!($strict, {
                        let result = super::strict_mont::strict_montgomery_mod_exp(base, &exponent, &modulus);
                        assert_eq!(result, expected);

                        // Verify against regular modular exponentiation
                        let regular_result = crate::exp::strict_mod_exp(base, &exponent, &modulus);
                        assert_eq!(result, regular_result);
                    });
                    let base = U256::from(base_val);
                    crate::maybe_test!($basic, {
                        let result = super::basic_montgomery_mod_exp(base, exponent, modulus);
                        assert_eq!(result, expected);

                        // Verify against regular modular exponentiation
                        let regular_result = crate::exp::basic_mod_exp(base, exponent, modulus);
                        assert_eq!(result, regular_result);
                    });
                }

                #[test]
                #[allow(unused_variables)]
                fn test_montgomery_parameter_computation() {
                    // Test Montgomery parameter computation for different moduli
                    let test_moduli = [U256::from(13u8), U256::from(17u8), U256::from(23u8)];

                    for modulus in test_moduli.iter() {
                        crate::maybe_test!($strict, {
                            let (r, r_inv, n_prime, r_bits) = super::strict_mont::strict_compute_montgomery_params(modulus);

                            // Verify mathematical properties
                            // 1. R * R^(-1) ≡ 1 (mod N)
                            assert_eq!((r * r_inv) % *modulus, U256::from(1u8));

                            // 2. N * N' ≡ -1 (mod R) which means N * N' ≡ R - 1 (mod R)
                            assert_eq!((*modulus * n_prime) % r, r - U256::from(1u8));

                            // 3. R should be > N and a power of 2
                            assert!(r > *modulus);
                            assert_eq!(r, U256::from(1u8) << r_bits);
                        });
                        crate::maybe_test!($basic, {
                            let (r, r_inv, n_prime, r_bits) = super::basic_compute_montgomery_params(*modulus);

                            // Verify mathematical properties
                            // 1. R * R^(-1) ≡ 1 (mod N)
                            assert_eq!((r * r_inv) % *modulus, U256::from(1u8));

                            // 2. N * N' ≡ -1 (mod R) which means N * N' ≡ R - 1 (mod R)
                            assert_eq!((*modulus * n_prime) % r, r - U256::from(1u8));

                            // 3. R should be > N and a power of 2
                            assert!(r > *modulus);
                            assert_eq!(r, U256::from(1u8) << r_bits);
                        });
                    }
                }

                #[test]
                #[allow(unused_variables)]
                fn test_montgomery_n_prime_methods() {
                    // Test that all N' computation methods produce identical results
                    let modulus = U256::from(13u8);

                    crate::maybe_test!($strict, {
                        let trial_result = super::strict_mont::strict_compute_montgomery_params_with_method(&modulus, super::NPrimeMethod::TrialSearch);
                        let euclidean_result = super::strict_mont::strict_compute_montgomery_params_with_method(&modulus, super::NPrimeMethod::ExtendedEuclidean);
                        let hensels_result = super::strict_mont::strict_compute_montgomery_params_with_method(&modulus, super::NPrimeMethod::HenselsLifting);

                        // All methods should produce identical results
                        assert_eq!(trial_result, euclidean_result);
                        assert_eq!(trial_result, hensels_result);
                        assert_eq!(euclidean_result, hensels_result);
                    });
                    crate::maybe_test!($basic, {
                        let trial_result = super::basic_compute_montgomery_params_with_method(modulus, super::NPrimeMethod::TrialSearch);
                        let euclidean_result = super::basic_compute_montgomery_params_with_method(modulus, super::NPrimeMethod::ExtendedEuclidean);
                        let hensels_result = super::basic_compute_montgomery_params_with_method(modulus, super::NPrimeMethod::HenselsLifting);

                        // All methods should produce identical results
                        assert_eq!(trial_result, euclidean_result);
                        assert_eq!(trial_result, hensels_result);
                        assert_eq!(euclidean_result, hensels_result);
                    });
                }

                #[test]
                #[allow(unused_variables)]
                fn test_montgomery_round_trip_conversions() {
                    // Test round-trip conversions: normal -> Montgomery -> normal
                    let modulus = U256::from(13u8);

                    crate::maybe_test!($strict, {
                        let (r, _r_inv, n_prime, r_bits) = super::strict_mont::strict_compute_montgomery_params(&modulus);

                        // Test values from 0 to modulus-1
                        for i in 0u8..13u8 {
                            let value = U256::from(i);
                            let montgomery_form = super::strict_mont::strict_to_montgomery(value, &modulus, &r);
                            let back_to_normal = super::strict_mont::strict_from_montgomery(montgomery_form, &modulus, &n_prime, r_bits);
                            assert_eq!(back_to_normal, value, "Round-trip failed for {}", i);
                        }
                    });
                    crate::maybe_test!($basic, {
                        let (r, _r_inv, n_prime, r_bits) = super::basic_compute_montgomery_params(modulus);

                        // Test values from 0 to modulus-1
                        for i in 0u8..13u8 {
                            let value = U256::from(i);
                            let montgomery_form = super::basic_to_montgomery(value, modulus, r);
                            let back_to_normal = super::basic_from_montgomery(montgomery_form, modulus, n_prime, r_bits);
                            assert_eq!(back_to_normal, value, "Round-trip failed for {}", i);
                        }
                    });
                }

                #[test]
                #[allow(unused_variables)]
                fn test_montgomery_comprehensive_multiplication() {
                    // Comprehensive test: verify Montgomery multiplication matches regular multiplication
                    let modulus = U256::from(13u8);

                    for a in 0u8..13u8 {
                        for b in 0u8..13u8 {
                            let a_big = U256::from(a);
                            let b_big = U256::from(b);
                            crate::maybe_test!($strict, {
                                let montgomery_result = super::strict_mont::strict_montgomery_mod_mul(a_big, &b_big, &modulus);
                                let regular_result = crate::mul::strict_mod_mul(a_big, &b_big, &modulus);
                                assert_eq!(montgomery_result, regular_result,
                                    "Montgomery vs regular mismatch: {} * {} mod 13: {:?} != {:?}",
                                    a, b, montgomery_result, regular_result);
                            });
                            let a_big = U256::from(a);
                            let b_big = U256::from(b);
                            crate::maybe_test!($basic, {
                                let montgomery_result = super::basic_montgomery_mod_mul(a_big, b_big, modulus);
                                let regular_result = crate::mul::basic_mod_mul(a_big, b_big, modulus);
                                assert_eq!(montgomery_result, regular_result,
                                    "Montgomery vs regular mismatch: {} * {} mod 13: {:?} != {:?}",
                                    a, b, montgomery_result, regular_result);
                            });
                        }
                    }
                }
            }
        }
    };
}

#[cfg(test)]
mod bnum_montgomery_tests {
    use super::*;

    montgomery_test_module!(
        bnum,
        bnum::types::U256,
        strict: off, // OverflowingAdd + OverflowingSub is not implemented
        basic: on,
    );

    montgomery_test_module!(
        bnum_patched,
        bnum_patched::types::U256,
        strict: off, // Complex trait bounds for Montgomery operations not fully compatible
        basic: on,
    );

    montgomery_test_module!(
        crypto_bigint,
        crypto_bigint::U256,
        strict: off, // OverflowingAdd + OverflowingSub is not implemented
        basic: off, // RemAssign and other traits missing
    );

    montgomery_test_module!(
        crypto_bigint_patched,
        crypto_bigint_patched::U256,
        strict: off, // &T + &T and &T - &T operations missing for Montgomery needs
        basic: on,
    );

    montgomery_test_module!(
        num_bigint,
        num_bigint::BigUint,
        type U256 = num_bigint::BigUint;
        strict: off, // OverflowingAdd + OverflowingSub is not implemented
        basic: off, // Copy is not implemented, heap allocation
    );

    montgomery_test_module!(
        num_bigint_patched,
        num_bigint_patched::BigUint,
        type U256 = num_bigint_patched::BigUint;
        strict: off, // Complex trait bounds for Montgomery operations not fully compatible
        basic: off, // Copy is not implemented, heap allocation
    );

    montgomery_test_module!(
        ibig,
        ibig::UBig,
        type U256 = ibig::UBig;
        strict: off, // OverflowingAdd + OverflowingSub is not implemented
        basic: off, // Copy is not implemented, heap allocation
    );

    montgomery_test_module!(
        ibig_patched,
        ibig_patched::UBig,
        type U256 = ibig_patched::UBig;
        strict: off, // Complex trait bounds for Montgomery operations not fully compatible
        basic: off, // Copy is not implemented, heap allocation
    );

    montgomery_test_module!(
        fixed_bigint,
        fixed_bigint::FixedUInt,
        type U256 = fixed_bigint::FixedUInt<u8, 4>;
        strict: on,
        basic: on,
    );
}
