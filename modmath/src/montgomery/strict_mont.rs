/// Compute N' using trial search method - O(R) complexity (Strict)
/// Finds N' such that modulus * N' ≡ -1 (mod R)
/// Uses reference-based operations to minimize copying of large integers
pub fn strict_compute_n_prime_trial_search<T>(modulus: &T, r: &T) -> T
where
    T: num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub,
    for<'a> T: core::ops::RemAssign<&'a T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>,
{
    // We need to find N' where modulus * N' ≡ R - 1 (mod R)
    let target = r - &T::one(); // This is -1 mod R

    // Simple trial search for N'
    // TODO: Replace with Extended Euclidean Algorithm for O(log R) complexity instead of O(R)
    // Current implementation is fine for small numbers but inefficient for large moduli
    let mut n_prime = T::one();
    loop {
        // Check if (modulus * n_prime) % r == target
        // Use references to avoid copying large integers
        let product = modulus * &n_prime;
        let remainder = &product % r;
        if remainder == target {
            return n_prime;
        }

        // Increment n_prime: n_prime = n_prime + 1
        // Use overflowing_add for strict arithmetic
        let (incremented, _overflow) = n_prime.overflowing_add(&T::one());
        n_prime = incremented;

        // Safety check to avoid infinite loop
        if &n_prime >= r {
            panic!("Could not find N' - should not happen for valid inputs");
        }
    }
}

/// Montgomery parameter computation (Strict)
/// Computes R, R^(-1) mod N, N', and R bit length for Montgomery arithmetic
/// Uses reference-based operations to minimize copying of large integers
pub fn strict_compute_montgomery_params<T>(modulus: &T) -> (T, T, T, usize)
where
    T: num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub,
    for<'a> T: core::ops::RemAssign<&'a T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::AddAssign<&'a T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Add<&'a T, Output = T>,
{
    // Step 1: Find R = 2^k where R > modulus
    let mut r = T::one();
    let mut r_bits = 0usize;

    while &r <= modulus {
        r = r << 1; // r *= 2
        r_bits += 1;
    }

    // Create a clone using reference-based addition to avoid moving r
    let r_clone = &r + &T::zero(); // Clone r using references

    // Step 2: Compute R^(-1) mod modulus using strict_mod_inv
    let r_inv =
        crate::inv::strict_mod_inv(r_clone, modulus).expect("R should always be invertible mod N");

    // Step 3: Compute N' using strict trial search
    let n_prime = strict_compute_n_prime_trial_search(modulus, &r);

    (r, r_inv, n_prime, r_bits)
}

/// Montgomery parameter computation with method selection (Strict)
/// Computes R, R^(-1) mod N, N', and R bit length for Montgomery arithmetic using specified method
/// Uses reference-based operations to minimize copying of large integers
pub fn strict_compute_montgomery_params_with_method<T>(
    modulus: &T,
    method: crate::montgomery::NPrimeMethod,
) -> (T, T, T, usize)
where
    T: num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub,
    for<'a> T: core::ops::RemAssign<&'a T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::AddAssign<&'a T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Add<&'a T, Output = T>,
{
    // Step 1: Find R = 2^k where R > modulus
    let mut r = T::one();
    let mut r_bits = 0usize;

    while &r <= modulus {
        r = r << 1; // r *= 2
        r_bits += 1;
    }

    // Create a clone using reference-based addition to avoid moving r
    let r_clone = &r + &T::zero(); // Clone r using references

    // Step 2: Compute R^(-1) mod modulus using strict_mod_inv
    let r_inv =
        crate::inv::strict_mod_inv(r_clone, modulus).expect("R should always be invertible mod N");

    // Step 3: Compute N' such that N * N' ≡ -1 (mod R) using selected method
    let n_prime = match method {
        crate::montgomery::NPrimeMethod::TrialSearch => {
            strict_compute_n_prime_trial_search(modulus, &r)
        }
        crate::montgomery::NPrimeMethod::ExtendedEuclidean => {
            // TODO: Implement strict Extended Euclidean for N' computation
            // For now, fall back to trial search
            strict_compute_n_prime_trial_search(modulus, &r)
        }
        crate::montgomery::NPrimeMethod::HenselsLifting => {
            // TODO: Implement strict Hensel's lifting for N' computation
            // For now, fall back to trial search
            strict_compute_n_prime_trial_search(modulus, &r)
        }
    };

    (r, r_inv, n_prime, r_bits)
}

/// Convert from Montgomery form (Strict): (a * R) -> a mod N
/// Uses Montgomery reduction algorithm with reference-based operations
/// to minimize copying of large integers
pub fn strict_from_montgomery<T>(a_mont: T, modulus: &T, n_prime: &T, r_bits: usize) -> T
where
    T: num_traits::Zero
        + num_traits::One
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + core::ops::Shr<usize, Output = T>
        + core::ops::Sub<Output = T>
        + num_traits::ops::overflowing::OverflowingAdd,
    for<'a> T: core::ops::Mul<&'a T, Output = T>
        + core::ops::RemAssign<&'a T>
        + core::ops::Sub<&'a T, Output = T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>,
{
    // Montgomery reduction algorithm:
    // Input: a_mont (Montgomery form), N (modulus), N', r_bits
    // 1. R = 2^r_bits
    // 2. m = (a_mont * N') mod R
    // 3. t = (a_mont + m * N) / R
    // 4. if t >= N then return t - N else return t

    let r = T::one() << r_bits; // R = 2^r_bits

    // Step 1: m = (a_mont * N') mod R
    // Use reference for a_mont to avoid moving it
    let product = &a_mont * n_prime;
    let m = &product % &r;

    // Step 2: t = (a_mont + m * N) / R
    // Use overflowing_add for strict arithmetic
    let m_times_n = m * modulus;
    let (sum, _overflow) = a_mont.overflowing_add(&m_times_n);
    let t = sum >> r_bits; // Divide by R = 2^r_bits

    // Step 3: Final reduction
    if &t >= modulus {
        t - modulus
    } else {
        t
    }
}

/// Convert to Montgomery form (Strict): a -> (a * R) mod N
/// Uses reference-based operations to minimize copying of large integers
pub fn strict_to_montgomery<T>(a: T, modulus: &T, r: &T) -> T
where
    T: PartialOrd
        + num_traits::Zero
        + num_traits::One
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub
        + core::ops::Shr<usize, Output = T>,
    for<'a> T: core::ops::RemAssign<&'a T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T> + core::ops::BitAnd<Output = T>,
{
    crate::mul::strict_mod_mul(a, r, modulus)
}

/// Complete Montgomery modular multiplication (Strict): A * B mod N
/// Uses reference-based operations throughout to minimize copying of large integers
pub fn strict_montgomery_mod_mul<T>(a: T, b: &T, modulus: &T) -> T
where
    T: num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Shr<usize, Output = T>
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub,
    for<'a> T: core::ops::RemAssign<&'a T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::AddAssign<&'a T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    // Step 1: Compute Montgomery parameters
    let (r, _r_inv, n_prime, r_bits) = strict_compute_montgomery_params(modulus);

    // Step 2: Convert inputs to Montgomery form
    let a_mont = strict_to_montgomery(a, modulus, &r);
    let b_clone = b + &T::zero(); // Clone b to pass by value
    let b_mont = strict_to_montgomery(b_clone, modulus, &r);

    // Step 3: Montgomery multiplication in Montgomery domain
    // a_mont * b_mont = (a*R) * (b*R) = a*b*R² mod N
    let product = crate::mul::strict_mod_mul(a_mont, &b_mont, modulus);

    // Apply Montgomery reduction once to get a*b*R mod N (still in Montgomery form)
    let result_mont = strict_from_montgomery(product, modulus, &n_prime, r_bits);

    // Step 4: Convert final result back from Montgomery form to get (a * b) mod N
    strict_from_montgomery(result_mont, modulus, &n_prime, r_bits)
}

/// Montgomery-based modular exponentiation (Strict): base^exponent mod modulus
/// Uses Montgomery arithmetic for efficient repeated multiplication with reference-based operations
/// to minimize copying of large integers
pub fn strict_montgomery_mod_exp<T>(mut base: T, exponent: &T, modulus: &T) -> T
where
    T: num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::Shr<usize, Output = T>
        + core::ops::ShrAssign<usize>
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub,
    for<'a> T: core::ops::RemAssign<&'a T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::AddAssign<&'a T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    // Step 1: Compute Montgomery parameters
    let (r, _r_inv, n_prime, r_bits) = strict_compute_montgomery_params(modulus);

    // Step 2: Reduce base and convert to Montgomery form
    base.rem_assign(modulus); // Reduce base first to ensure base < modulus
    base = strict_to_montgomery(base, modulus, &r);

    // Step 3: Initialize result to Montgomery form of 1
    let mut result = strict_to_montgomery(T::one(), modulus, &r);

    // Step 4: Clone exponent for manipulation to avoid moving the reference
    let mut exp = exponent + &T::zero(); // Clone exponent

    // Step 5: Binary exponentiation using Montgomery multiplication
    while exp > T::zero() {
        // If exponent is odd, multiply result by current base power
        if &exp & &T::one() == T::one() {
            result = strict_montgomery_mod_mul_internal(result, &base, modulus, &n_prime, r_bits);
        }

        // Square the base for next iteration
        exp >>= 1;
        if exp > T::zero() {
            let base_clone = &base + &T::zero(); // Clone base using references
            base = strict_montgomery_mod_mul_internal(base, &base_clone, modulus, &n_prime, r_bits);
        }
    }

    // Step 6: Convert result back from Montgomery form
    strict_from_montgomery(result, modulus, &n_prime, r_bits)
}

/// Internal Montgomery multiplication for use within strict_montgomery_mod_exp
/// This avoids recomputing Montgomery parameters on each multiplication
fn strict_montgomery_mod_mul_internal<T>(
    a_mont: T,
    b_mont: &T,
    modulus: &T,
    n_prime: &T,
    r_bits: usize,
) -> T
where
    T: num_traits::Zero
        + num_traits::One
        + PartialOrd
        + core::ops::Shl<usize, Output = T>
        + core::ops::Shr<usize, Output = T>
        + core::ops::Sub<Output = T>
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub,
    for<'a> T: core::ops::RemAssign<&'a T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>,
    for<'a> &'a T: core::ops::Rem<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::BitAnd<Output = T>,
{
    // Montgomery multiplication in Montgomery domain
    // a_mont and b_mont are already in Montgomery form
    // Result should be (a * b * R) mod N (still in Montgomery form)

    // Step 1: Regular modular multiplication: (a_mont * b_mont) mod N
    let product = crate::mul::strict_mod_mul(a_mont, b_mont, modulus);

    // Step 2: Apply Montgomery reduction once to get (a * b * R) mod N
    strict_from_montgomery(product, modulus, n_prime, r_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_compute_n_prime_trial_search() {
        let modulus = 13u32;
        let r = 16u32;
        let n_prime = strict_compute_n_prime_trial_search(&modulus, &r);
        assert_eq!(n_prime, 11);
    }

    #[test]
    fn test_strict_with_fixed_bigint() {
        type U256 = fixed_bigint::FixedUInt<u32, 4>;
        let modulus = U256::from(13u32);
        let r = U256::from(16u32);
        let n_prime = strict_compute_n_prime_trial_search(&modulus, &r);
        assert_eq!(n_prime, U256::from(11u32));
    }

    #[test]
    fn test_strict_compute_montgomery_params() {
        // Test with our documented example: N = 13
        // Expected: R = 16, R^(-1) = 9, N' = 11, r_bits = 4
        let modulus = 13u32;
        let (r, r_inv, n_prime, r_bits) = strict_compute_montgomery_params(&modulus);

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
    fn test_strict_compute_montgomery_params_with_method() {
        // Test that the parametrized version produces identical results
        let modulus = 13u32;
        let default_result = strict_compute_montgomery_params(&modulus);
        let explicit_trial_result = strict_compute_montgomery_params_with_method(
            &modulus,
            crate::montgomery::NPrimeMethod::TrialSearch,
        );

        // Both should produce identical results since TrialSearch is the default
        assert_eq!(default_result, explicit_trial_result);

        // Verify the explicit method call produces correct values
        let (r, r_inv, n_prime, r_bits) = explicit_trial_result;
        assert_eq!(r, 16);
        assert_eq!(r_inv, 9);
        assert_eq!(n_prime, 11);
        assert_eq!(r_bits, 4);

        // Test that all methods produce the same result (for now they all use trial search)
        let euclidean_result = strict_compute_montgomery_params_with_method(
            &modulus,
            crate::montgomery::NPrimeMethod::ExtendedEuclidean,
        );
        let hensels_result = strict_compute_montgomery_params_with_method(
            &modulus,
            crate::montgomery::NPrimeMethod::HenselsLifting,
        );

        assert_eq!(default_result, euclidean_result);
        assert_eq!(default_result, hensels_result);
    }

    #[test]
    fn test_strict_montgomery_params_with_fixed_bigint() {
        type U256 = fixed_bigint::FixedUInt<u32, 4>;
        let modulus = U256::from(13u32);
        let (r, r_inv, n_prime, r_bits) = strict_compute_montgomery_params(&modulus);

        assert_eq!(r, U256::from(16u32));
        assert_eq!(r_inv, U256::from(9u32));
        assert_eq!(n_prime, U256::from(11u32));
        assert_eq!(r_bits, 4);

        // Verify mathematical properties
        let thirteen = U256::from(13u32);
        let one = U256::from(1u32);

        // R * R^(-1) ≡ 1 (mod N)
        assert_eq!((r * r_inv) % thirteen, one);

        // N * N' ≡ -1 (mod R) which means N * N' ≡ R - 1 (mod R)
        assert_eq!((thirteen * n_prime) % r, r - one);

        // R should be > N and a power of 2
        assert!(r > thirteen);
        assert_eq!(r, one << r_bits);
    }

    #[test]
    fn test_strict_from_montgomery() {
        // Test with our documented example: N = 13
        let modulus = 13u32;
        let (_r, _r_inv, n_prime, r_bits) = strict_compute_montgomery_params(&modulus);

        // Test conversion from Montgomery form back to normal form
        // We know from the basic tests that 7 -> Montgomery form is 8
        // So 8 -> normal form should be 7
        let mont_form = 8u32; // This is 7 in Montgomery form
        let normal_form = strict_from_montgomery(mont_form, &modulus, &n_prime, r_bits);
        assert_eq!(normal_form, 7u32);

        // Test with 5 -> Montgomery (2) -> back to normal (should be 5)
        let mont_5 = 2u32; // This is 5 in Montgomery form
        let normal_5 = strict_from_montgomery(mont_5, &modulus, &n_prime, r_bits);
        assert_eq!(normal_5, 5u32);

        // Test edge cases
        let mont_0 = 0u32; // 0 in Montgomery form is still 0
        let normal_0 = strict_from_montgomery(mont_0, &modulus, &n_prime, r_bits);
        assert_eq!(normal_0, 0u32);
    }

    #[test]
    fn test_strict_from_montgomery_with_fixed_bigint() {
        type U256 = fixed_bigint::FixedUInt<u32, 4>;
        let modulus = U256::from(13u32);
        let (_r, _r_inv, n_prime, r_bits) = strict_compute_montgomery_params(&modulus);

        // Test conversion from Montgomery form back to normal form
        let mont_form = U256::from(8u32); // This is 7 in Montgomery form
        let normal_form = strict_from_montgomery(mont_form, &modulus, &n_prime, r_bits);
        assert_eq!(normal_form, U256::from(7u32));

        let mont_5 = U256::from(2u32); // This is 5 in Montgomery form
        let normal_5 = strict_from_montgomery(mont_5, &modulus, &n_prime, r_bits);
        assert_eq!(normal_5, U256::from(5u32));

        // Test edge case
        let mont_0 = U256::from(0u32);
        let normal_0 = strict_from_montgomery(mont_0, &modulus, &n_prime, r_bits);
        assert_eq!(normal_0, U256::from(0u32));
    }

    #[test]
    fn test_strict_round_trip_conversion() {
        // Test round-trip: normal -> Montgomery -> normal using strict functions
        // We'll need to implement strict_to_montgomery first to complete this test
        // For now, we can verify that from_montgomery works with known Montgomery values

        let modulus = 13u32;
        let (r, _r_inv, n_prime, r_bits) = strict_compute_montgomery_params(&modulus);

        // Test all values 0..13 using basic_to_montgomery to get Montgomery form,
        // then strict_from_montgomery to get back to normal
        for i in 0u32..13u32 {
            // Use basic function to convert to Montgomery form
            let mont = crate::montgomery::basic_mont::basic_to_montgomery(i, modulus, r);
            // Use strict function to convert back
            let back = strict_from_montgomery(mont, &modulus, &n_prime, r_bits);
            assert_eq!(
                back, i,
                "Round-trip failed for {}: {} -> {} -> {}",
                i, i, mont, back
            );
        }
    }

    #[test]
    fn test_strict_to_montgomery() {
        // Test with our documented example: N = 13, R = 16
        let modulus = 13u32;
        let (r, _r_inv, _n_prime, _r_bits) = strict_compute_montgomery_params(&modulus);

        // From EXAMPLE1_COMPUTE_PARAM.md:
        // 7 -> Montgomery: 7 * 16 mod 13 = 112 mod 13 = 8
        // 5 -> Montgomery: 5 * 16 mod 13 = 80 mod 13 = 2
        assert_eq!(strict_to_montgomery(7u32, &modulus, &r), 8u32);
        assert_eq!(strict_to_montgomery(5u32, &modulus, &r), 2u32);

        // Test edge cases
        assert_eq!(strict_to_montgomery(0u32, &modulus, &r), 0u32); // 0 * R mod N = 0
        assert_eq!(strict_to_montgomery(1u32, &modulus, &r), 3u32); // 1 * 16 mod 13 = 3
    }

    #[test]
    fn test_strict_to_montgomery_with_fixed_bigint() {
        type U256 = fixed_bigint::FixedUInt<u32, 4>;
        let modulus = U256::from(13u32);
        let (r, _r_inv, _n_prime, _r_bits) = strict_compute_montgomery_params(&modulus);

        // Test conversions
        assert_eq!(
            strict_to_montgomery(U256::from(7u32), &modulus, &r),
            U256::from(8u32)
        );
        assert_eq!(
            strict_to_montgomery(U256::from(5u32), &modulus, &r),
            U256::from(2u32)
        );
        assert_eq!(
            strict_to_montgomery(U256::from(0u32), &modulus, &r),
            U256::from(0u32)
        );
        assert_eq!(
            strict_to_montgomery(U256::from(1u32), &modulus, &r),
            U256::from(3u32)
        );
    }

    #[test]
    fn test_strict_montgomery_mod_mul() {
        // Test the complete strict Montgomery workflow end-to-end
        let modulus = 13u32;

        // Test: 7 * 5 mod 13 = 9
        let a = 7u32;
        let b = 5u32;
        let result = strict_montgomery_mod_mul(a, &b, &modulus);
        assert_eq!(result, 9u32);

        // Verify against regular modular multiplication
        let regular_result = crate::mul::strict_mod_mul(a, &b, &modulus);
        assert_eq!(result, regular_result);

        // Test more cases to ensure correctness
        let test_cases = [
            (0u32, 5u32, 0u32),   // 0 * 5 mod 13 = 0
            (7u32, 0u32, 0u32),   // 7 * 0 mod 13 = 0
            (1u32, 7u32, 7u32),   // 1 * 7 mod 13 = 7
            (7u32, 1u32, 7u32),   // 7 * 1 mod 13 = 7
            (12u32, 12u32, 1u32), // 12 * 12 mod 13 = 144 mod 13 = 1
            (6u32, 9u32, 2u32),   // 6 * 9 mod 13 = 54 mod 13 = 2
        ];

        for (a, b, expected) in test_cases.iter() {
            let result = strict_montgomery_mod_mul(*a, b, &modulus);
            assert_eq!(result, *expected, "Failed for {} * {} mod 13", a, b);
        }
    }

    #[test]
    fn test_strict_montgomery_mod_mul_with_fixed_bigint() {
        type U256 = fixed_bigint::FixedUInt<u32, 4>;
        let modulus = U256::from(13u32);

        // Test: 7 * 5 mod 13 = 9
        let a = U256::from(7u32);
        let b = U256::from(5u32);
        let result = strict_montgomery_mod_mul(a, &b, &modulus);
        assert_eq!(result, U256::from(9u32));

        // Verify against regular modular multiplication
        let regular_result = crate::mul::strict_mod_mul(U256::from(7u32), &b, &modulus);
        assert_eq!(result, regular_result);
    }

    #[test]
    fn test_strict_complete_round_trip() {
        // Test the complete workflow: to_montgomery -> from_montgomery
        let modulus = 13u32;
        let (r, _r_inv, n_prime, r_bits) = strict_compute_montgomery_params(&modulus);

        // Test all values 0..13 for complete round-trip
        for i in 0u32..13u32 {
            let mont = strict_to_montgomery(i, &modulus, &r);
            let back = strict_from_montgomery(mont, &modulus, &n_prime, r_bits);
            assert_eq!(
                back, i,
                "Complete round-trip failed for {}: {} -> {} -> {}",
                i, i, mont, back
            );
        }
    }

    #[test]
    fn test_strict_montgomery_mod_exp() {
        // Test Montgomery-based exponentiation against regular exponentiation
        let modulus = 13u32;

        // Test: 7^5 mod 13 = 16807 mod 13 = 11
        let base = 7u32;
        let exponent = 5u32;
        let montgomery_result = strict_montgomery_mod_exp(base, &exponent, &modulus);
        let regular_result = crate::exp::strict_mod_exp(base, &exponent, &modulus);
        assert_eq!(montgomery_result, regular_result);
        assert_eq!(montgomery_result, 11u32);

        // Test edge cases
        assert_eq!(strict_montgomery_mod_exp(0u32, &5u32, &modulus), 0u32); // 0^5 = 0
        assert_eq!(strict_montgomery_mod_exp(7u32, &0u32, &modulus), 1u32); // 7^0 = 1
        assert_eq!(strict_montgomery_mod_exp(1u32, &100u32, &modulus), 1u32); // 1^100 = 1
        assert_eq!(strict_montgomery_mod_exp(7u32, &1u32, &modulus), 7u32); // 7^1 = 7

        // Test more cases
        let test_cases = [
            (2u32, 10u32, 13u32, 10u32), // 2^10 mod 13 = 1024 mod 13 = 10
            (3u32, 4u32, 13u32, 3u32),   // 3^4 mod 13 = 81 mod 13 = 3
            (12u32, 2u32, 13u32, 1u32),  // 12^2 mod 13 = 144 mod 13 = 1
            (5u32, 3u32, 13u32, 8u32),   // 5^3 mod 13 = 125 mod 13 = 8
        ];

        for (base, exp, mod_val, expected) in test_cases.iter() {
            let result = strict_montgomery_mod_exp(*base, exp, mod_val);
            assert_eq!(
                result, *expected,
                "Failed for {}^{} mod {}",
                base, exp, mod_val
            );
        }
    }

    #[test]
    fn test_strict_montgomery_mod_exp_with_fixed_bigint() {
        type U256 = fixed_bigint::FixedUInt<u32, 4>;
        let modulus = U256::from(13u32);

        // Test: 7^5 mod 13 = 11
        let base = U256::from(7u32);
        let exponent = U256::from(5u32);
        let montgomery_result = strict_montgomery_mod_exp(base, &exponent, &modulus);
        let regular_result = crate::exp::strict_mod_exp(U256::from(7u32), &exponent, &modulus);
        assert_eq!(montgomery_result, regular_result);
        assert_eq!(montgomery_result, U256::from(11u32));

        // Test edge cases
        assert_eq!(
            strict_montgomery_mod_exp(U256::from(0u32), &U256::from(5u32), &modulus),
            U256::from(0u32)
        ); // 0^5 = 0

        assert_eq!(
            strict_montgomery_mod_exp(U256::from(7u32), &U256::from(0u32), &modulus),
            U256::from(1u32)
        ); // 7^0 = 1

        assert_eq!(
            strict_montgomery_mod_exp(U256::from(1u32), &U256::from(100u32), &modulus),
            U256::from(1u32)
        ); // 1^100 = 1
    }

    #[test]
    fn test_strict_montgomery_mod_exp_comprehensive() {
        // Comprehensive test: verify Montgomery exp matches regular exp for all small values
        let modulus = 13u32;

        for base in 0u32..13u32 {
            for exponent in 0u32..10u32 {
                let montgomery_result = strict_montgomery_mod_exp(base, &exponent, &modulus);
                let regular_result = crate::exp::strict_mod_exp(base, &exponent, &modulus);
                assert_eq!(
                    montgomery_result, regular_result,
                    "Montgomery vs regular exp mismatch: {}^{} mod 13: {} != {}",
                    base, exponent, montgomery_result, regular_result
                );
            }
        }
    }

    #[test]
    fn test_strict_montgomery_mod_exp_large_exponents() {
        // Test with larger exponents to verify efficiency benefits would apply
        let modulus = 13u32;

        assert_eq!(
            strict_montgomery_mod_exp(2u32, &100u32, &modulus),
            crate::exp::strict_mod_exp(2u32, &100u32, &modulus)
        );

        assert_eq!(
            strict_montgomery_mod_exp(3u32, &1000u32, &modulus),
            crate::exp::strict_mod_exp(3u32, &1000u32, &modulus)
        );

        // Test with very large exponent
        assert_eq!(
            strict_montgomery_mod_exp(7u32, &999999u32, &modulus),
            crate::exp::strict_mod_exp(7u32, &999999u32, &modulus)
        );
    }

    #[test]
    fn test_strict_montgomery_internal_mul() {
        // Test the internal Montgomery multiplication function
        let modulus = 13u32;
        let (r, _r_inv, n_prime, r_bits) = strict_compute_montgomery_params(&modulus);

        // Convert values to Montgomery form
        let a_mont = strict_to_montgomery(7u32, &modulus, &r);
        let b_mont = strict_to_montgomery(5u32, &modulus, &r);

        // Use internal multiplication (should stay in Montgomery form)
        let result_mont =
            strict_montgomery_mod_mul_internal(a_mont, &b_mont, &modulus, &n_prime, r_bits);

        // Convert back to normal form to verify
        let result = strict_from_montgomery(result_mont, &modulus, &n_prime, r_bits);
        assert_eq!(result, 9u32); // 7 * 5 mod 13 = 9
    }
}
