// Montgomery form arithmetic functions
//
// This module provides Montgomery form arithmetic following the same
// constraint pattern as the rest of the library.

/// Methods for computing N' in Montgomery parameter computation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NPrimeMethod {
    /// Trial search - O(R) complexity, simple but slow for large R
    TrialSearch,
    /// Extended Euclidean Algorithm - O(log R) complexity (future implementation)
    ExtendedEuclidean,
    /// Hensel's lifting - O(log R) complexity, optimized for R = 2^k (future implementation)
    HenselsLifting,
}

impl Default for NPrimeMethod {
    fn default() -> Self {
        NPrimeMethod::TrialSearch
    }
}

/// Compute N' using trial search method - O(R) complexity
/// Finds N' such that modulus * N' ≡ -1 (mod R)
fn compute_n_prime_trial_search<T>(modulus: T, r: T) -> T
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Add<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Mul<Output = T>
        + core::ops::Rem<Output = T>,
{
    // We need to find N' where modulus * N' ≡ R - 1 (mod R)
    let target = r - T::one(); // This is -1 mod R

    // Simple trial search for N'
    // TODO: Replace with Extended Euclidean Algorithm for O(log R) complexity instead of O(R)
    // Current implementation is fine for small numbers but inefficient for large moduli
    let mut n_prime = T::one();
    loop {
        if (modulus * n_prime) % r == target {
            return n_prime;
        }
        n_prime = n_prime + T::one();

        // Safety check to avoid infinite loop
        if n_prime >= r {
            panic!("Could not find N' - should not happen for valid inputs");
        }
    }
}

/// Compute N' using Extended Euclidean Algorithm - O(log R) complexity
/// Finds N' such that modulus * N' ≡ -1 (mod R)
/// This is equivalent to N' ≡ -modulus^(-1) (mod R)
fn compute_n_prime_extended_euclidean<T>(modulus: T, r: T) -> T
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Add<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Mul<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::Div<Output = T>,
{
    // We need to solve: modulus * N' ≡ -1 (mod R)
    // This is equivalent to: modulus * N' ≡ R - 1 (mod R)
    // So: N' ≡ (R - 1) * modulus^(-1) (mod R)
    // Or: N' ≡ -modulus^(-1) (mod R)

    // Use basic_mod_inv to find modulus^(-1) mod R
    if let Some(modulus_inv) = crate::inv::basic_mod_inv(modulus, r) {
        // N' = -modulus^(-1) mod R = R - modulus^(-1) mod R
        if modulus_inv == T::zero() {
            r - T::one() // Handle edge case where inverse is 0
        } else {
            r - modulus_inv
        }
    } else {
        panic!("Could not find modular inverse - gcd(modulus, R) should be 1 for valid Montgomery parameters");
    }
}

/// Compute N' using Hensel's lifting - O(log R) complexity, optimized for R = 2^k
/// Finds N' such that modulus * N' ≡ -1 (mod R)
/// Uses Newton's method to iteratively lift from small powers to full R
fn compute_n_prime_hensels_lifting<T>(modulus: T, r: T, r_bits: usize) -> T
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Add<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Mul<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::Shl<usize, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    // Hensel's lifting for N' computation when R = 2^k
    // Start with base case: find N' such that modulus * N' ≡ -1 (mod 2)
    // Then iteratively lift to larger powers of 2

    // Base case: modulus * N' ≡ -1 ≡ 1 (mod 2)
    // Since modulus is odd (required for Montgomery), modulus ≡ 1 (mod 2)
    // So we need N' ≡ 1 (mod 2), hence N' starts as 1
    let mut n_prime = T::one();

    // Lift from 2^1 to 2^r_bits using Newton's method
    for k in 2..=r_bits {
        // We have: modulus * n_prime ≡ -1 (mod 2^(k-1))
        // We want: modulus * n_prime_new ≡ -1 (mod 2^k)

        // Newton iteration: x_new = x - f(x)/f'(x)
        // Where f(x) = modulus * x + 1
        // f'(x) = modulus
        // So: x_new = x - (modulus * x + 1) / modulus
        //     x_new = x - x - 1/modulus  (but we work mod powers of 2)

        let target_mod = T::one() << k; // 2^k
        let check_val = (modulus * n_prime + T::one()) % target_mod;

        if check_val != T::zero() {
            // Need to adjust n_prime
            // If modulus * n_prime + 1 = t * 2^(k-1) for odd t, add 2^(k-1) to n_prime
            let prev_power = T::one() << (k - 1); // 2^(k-1)

            if check_val == prev_power {
                n_prime = n_prime + prev_power;
            }
        }
    }

    // Final check and adjustment to ensure modulus * N' ≡ -1 (mod R)
    let final_check = (modulus * n_prime) % r;
    let target = r - T::one(); // -1 mod R

    if final_check != target {
        // This shouldn't happen with correct Hensel lifting, but safety check
        panic!("Hensel lifting failed to produce correct N'");
    }

    n_prime
}

/// Montgomery parameter computation (Basic)
/// Computes R, R^(-1) mod N, N', and R bit length for Montgomery arithmetic
pub fn basic_compute_montgomery_params_with_method<T>(
    modulus: T,
    method: NPrimeMethod,
) -> (T, T, T, usize)
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + core::ops::Div<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Mul<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::Add<Output = T>
        + core::ops::BitAnd<Output = T>,
{
    use crate::inv::basic_mod_inv;

    // Step 1: Find R = 2^k where R > modulus
    let mut r = T::one();
    let mut r_bits = 0usize;

    while r <= modulus {
        r = r << 1; // r *= 2
        r_bits += 1;
    }

    // Step 2: Compute R^(-1) mod modulus
    let r_inv = basic_mod_inv(r, modulus).expect("R should always be invertible mod N");

    // Step 3: Compute N' such that N * N' ≡ -1 (mod R) using selected method
    let n_prime = match method {
        NPrimeMethod::TrialSearch => compute_n_prime_trial_search(modulus, r),
        NPrimeMethod::ExtendedEuclidean => compute_n_prime_extended_euclidean(modulus, r),
        NPrimeMethod::HenselsLifting => compute_n_prime_hensels_lifting(modulus, r, r_bits),
    };

    (r, r_inv, n_prime, r_bits)
}

/// Montgomery parameter computation (Basic) with default method
/// Computes R, R^(-1) mod N, N', and R bit length for Montgomery arithmetic using trial search
pub fn basic_compute_montgomery_params<T>(modulus: T) -> (T, T, T, usize)
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + core::ops::Div<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Mul<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::Add<Output = T>
        + core::ops::BitAnd<Output = T>,
{
    basic_compute_montgomery_params_with_method(modulus, NPrimeMethod::default())
}

/// Convert to Montgomery form (Basic): a -> (a * R) mod N
pub fn basic_to_montgomery<T>(a: T, modulus: T, r: T) -> T
where
    T: core::cmp::PartialOrd
        + Copy
        + num_traits::Zero
        + num_traits::One
        + core::ops::BitAnd<Output = T>
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub
        + core::ops::Shr<usize, Output = T>
        + core::ops::Rem<Output = T>,
{
    crate::mul::basic_mod_mul(a, r, modulus)
}

/// Convert from Montgomery form (Basic): (a * R) -> a mod N
/// Uses Montgomery reduction algorithm
pub fn basic_from_montgomery<T>(a_mont: T, modulus: T, n_prime: T, r_bits: usize) -> T
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialOrd
        + core::ops::Mul<Output = T>
        + core::ops::Add<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::Shr<usize, Output = T>
        + core::ops::Shl<usize, Output = T>,
{
    // Montgomery reduction algorithm:
    // Input: a_mont (Montgomery form), N (modulus), N', r_bits
    // 1. R = 2^r_bits
    // 2. m = (a_mont * N') mod R
    // 3. t = (a_mont + m * N) / R
    // 4. if t >= N then return t - N else return t

    let r = T::one() << r_bits; // R = 2^r_bits

    // Step 1: m = (a_mont * N') mod R
    let m = (a_mont * n_prime) % r;

    // Step 2: t = (a_mont + m * N) / R
    let t = (a_mont + m * modulus) >> r_bits; // Divide by R = 2^r_bits

    // Step 3: Final reduction
    if t >= modulus {
        t - modulus
    } else {
        t
    }
}

/// Montgomery multiplication (Basic): (a * R) * (b * R) -> (a * b * R) mod N
pub fn basic_montgomery_mul<T>(a_mont: T, b_mont: T, modulus: T, n_prime: T, r_bits: usize) -> T
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialOrd
        + core::ops::Mul<Output = T>
        + core::ops::Add<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::Shr<usize, Output = T>
        + core::ops::Shl<usize, Output = T>
        + core::ops::BitAnd<Output = T>
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub,
{
    // Montgomery multiplication algorithm:
    // Input: a_mont, b_mont (both in Montgomery form), modulus N, N', r_bits
    // 1. Compute product = a_mont * b_mont (mod N)
    // 2. Apply Montgomery reduction to get (a * b * R) mod N

    // Step 1: Regular modular multiplication in Montgomery domain
    let product = crate::mul::basic_mod_mul(a_mont, b_mont, modulus);

    // Step 2: Apply Montgomery reduction to get result in Montgomery form
    basic_from_montgomery(product, modulus, n_prime, r_bits)
}

/// Complete Montgomery modular multiplication (Basic): A * B mod N
pub fn basic_montgomery_mod_mul<T>(a: T, b: T, modulus: T) -> T
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + core::ops::Div<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Mul<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::BitAnd<Output = T>
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub
        + core::ops::Shr<usize, Output = T>,
{
    let (r, _r_inv, n_prime, r_bits) = basic_compute_montgomery_params(modulus);
    let a_mont = basic_to_montgomery(a, modulus, r);
    let b_mont = basic_to_montgomery(b, modulus, r);
    let result_mont = basic_montgomery_mul(a_mont, b_mont, modulus, n_prime, r_bits);
    basic_from_montgomery(result_mont, modulus, n_prime, r_bits)
}

/// Montgomery-based modular exponentiation (Basic): base^exponent mod modulus
/// Uses Montgomery arithmetic for efficient repeated multiplication
pub fn basic_montgomery_mod_exp<T>(mut base: T, exponent: T, modulus: T) -> T
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + core::ops::Div<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Mul<Output = T>
        + core::ops::Rem<Output = T>
        + core::ops::BitAnd<Output = T>
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub
        + core::ops::Shr<usize, Output = T>
        + core::ops::ShrAssign<usize>,
{
    // Compute Montgomery parameters
    let (r, _r_inv, n_prime, r_bits) = basic_compute_montgomery_params(modulus);

    // Convert base to Montgomery form
    base = basic_to_montgomery(base % modulus, modulus, r); // Reduce base first

    // Montgomery form of 1 (the initial result)
    let mut result = basic_to_montgomery(T::one(), modulus, r);

    // Copy exponent for manipulation
    let mut exp = exponent;

    // Binary exponentiation using Montgomery multiplication
    while exp > T::zero() {
        // If exponent is odd, multiply result by current base power
        if exp & T::one() == T::one() {
            result = basic_montgomery_mul(result, base, modulus, n_prime, r_bits);
        }

        // Square the base for next iteration
        exp >>= 1;
        if exp > T::zero() {
            base = basic_montgomery_mul(base, base, modulus, n_prime, r_bits);
        }
    }

    // Convert result back from Montgomery form
    basic_from_montgomery(result, modulus, n_prime, r_bits)
}

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
