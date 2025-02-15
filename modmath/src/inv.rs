mod signed;
use signed::Signed;

/*
Based on this pseudocode:

function inverse(a, n)
    t := 0;     newt := 1
    r := n;     newr := a

    while newr ≠ 0 do
        quotient := r div newr
        (t, newt) := (newt, t − quotient × newt)
        (r, newr) := (newr, r − quotient × newr)

    if r > 1 then
        return "a is not invertible"
    if t < 0 then
        t := t + n

    return t
*/

/// # Modular Inverse (Strict)
/// Most constrained version that works with references. Requires
/// reference-based operations for division and subtraction.
pub fn strict_mod_inv<T>(a: T, modulus: &T) -> Option<T>
where
    T: num_traits::Zero
        + num_traits::One
        + PartialEq
        + core::ops::Sub<Output = T>
        + core::cmp::PartialOrd,
    for<'a> T: core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::AddAssign<&'a T>
        + core::cmp::PartialOrd,
    for<'a> &'a T: core::ops::Div<&'a T, Output = T> + core::ops::Sub<T, Output = T>,
{
    let mut t = Signed::new(T::zero(), false);
    let mut new_t = Signed::new(T::one(), false);
    // makes a clone of modulus
    let mut r = T::zero() + modulus;
    let mut new_r = a;

    while new_r != T::zero() {
        let quotient = &r / &new_r;

        // clone
        let tmp_t = Signed::new(T::zero(), false) + &new_t;
        new_t = t - new_t * &quotient;
        t = tmp_t;

        // clone
        let tmp_r = T::zero() + &new_r;
        new_r = r - new_r * &quotient;
        r = tmp_r;
    }

    if r > T::one() {
        return None;
    }

    if t < T::zero().into() {
        t = t + modulus;
    }

    Some(t.into_inner())
}

// Another version with less constraints
// Still uses input references. Requires Clone

/// # Modular Inverse (Constrained)
/// Version that works with references. Requires Clone and
/// reference-based operations.
pub fn constrained_mod_inv<T>(a: T, modulus: &T) -> Option<T>
where
    T: num_traits::Zero
        + num_traits::One
        + Clone
        + PartialEq
        + core::cmp::PartialOrd
        + core::ops::Sub<Output = T>,
    for<'a> T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
    for<'a> &'a T: core::ops::Sub<T, Output = T> + core::ops::Div<&'a T, Output = T>,
{
    let mut t = Signed::new(T::zero(), false);
    let mut new_t = Signed::new(T::one(), false);
    let mut r = modulus.clone();
    let mut new_r = a;

    while new_r != T::zero() {
        let quotient = &r / &new_r;

        let tmp_t = new_t.clone();
        new_t = t - new_t * quotient.clone();
        t = tmp_t;

        let tmp_r = new_r.clone();
        new_r = r - new_r * quotient;
        r = tmp_r;
    }

    if r > T::one() {
        return None;
    }

    if t < T::zero().into() {
        t = t + modulus;
    }

    Some(t.into_inner())
}

/// # Modular Inverse (Basic)
/// Simple version that operates on values and copies them.
pub fn basic_mod_inv<T>(a: T, modulus: T) -> Option<T>
where
    T: num_traits::Zero
        + num_traits::One
        + Copy
        + PartialEq
        + core::ops::Div<Output = T>
        + core::ops::Sub<Output = T>
        + core::cmp::PartialOrd,
{
    let mut t = Signed::new(T::zero(), false);
    let mut new_t = Signed::new(T::one(), false);
    let mut r = Signed::new(modulus, false);
    let mut new_r = Signed::new(a, false);

    while new_r != Signed::new(T::zero(), false) {
        let quotient = r / new_r;

        let tmp_t = new_t;
        new_t = t - new_t * quotient;
        t = tmp_t;

        let tmp_r = new_r;
        new_r = r - new_r * quotient;
        r = tmp_r;
    }

    if r > T::one().into() {
        return None;
    }

    if t < T::zero().into() {
        t = t + modulus.into();
    }

    Some(t.into_inner())
}

#[cfg(test)]
macro_rules! select_mod_inv {
    ($mod_inv:path, $t:ty, by_ref) => {
        fn mod_inv(a: $t, modulus: &$t) -> Option<$t> {
            $mod_inv(a, modulus)
        }
    };
    ($mod_inv:path, $t:ty, by_val) => {
        fn mod_inv(a: $t, modulus: &$t) -> Option<$t> {
            $mod_inv(a, *modulus)
        }
    };
}

#[cfg(test)]
macro_rules! generate_mod_inv_tests_block_1 {
    ($mod_inv:path, $t:ty , $by_ref:tt) => {
        select_mod_inv!($mod_inv, $t, $by_ref);

        #[test]
        fn test_mod_inv_1_mod_13() {
            assert_eq!(mod_inv(0u32, &7u32), None);
            assert_eq!(mod_inv(1u32, &7u32).unwrap(), 1);
            assert_eq!(mod_inv(6u32, &8u32), None);
            assert_eq!(mod_inv(1u32, &13u32).unwrap(), 1u32); // 1 * 1 ≡ 1 (mod 13)
            assert_eq!(mod_inv(8u32, &13u32).unwrap(), 5u32); // Check: 8×5=40≡1mod  13.8×5=40≡1mod13.
            assert_eq!(mod_inv(12u32, &13u32).unwrap(), 12u32); // 1 * 1 ≡ 1 (mod 13)
            assert_eq!(mod_inv(14u32, &13u32).unwrap(), 1); // 14 * 10 ≡ 1 (mod 13)
            assert_eq!(mod_inv(15u32, &13u32).unwrap(), 7u32); // 15 * 9 ≡ 1 (mod 13)
            assert_eq!(mod_inv(16u32, &13u32).unwrap(), 9u32); // 16 * 8 ≡ 1 (mod 13)
            assert_eq!(mod_inv(10u32, &17).unwrap(), 12);
        }
    };
}

#[cfg(test)]
mod strict_mod_inv_tests {
    generate_mod_inv_tests_block_1!(super::strict_mod_inv, u32, by_ref);
}

#[cfg(test)]
mod constrained_mod_inv_tests {
    generate_mod_inv_tests_block_1!(super::constrained_mod_inv, u32, by_ref);
}

#[cfg(test)]
mod basic_mod_inv_tests {
    generate_mod_inv_tests_block_1!(super::basic_mod_inv, u32, by_val);
}

#[cfg(test)]
macro_rules! inv_test_module {
    (
        $stem:ident,
        $type_path:path,
        $(type $type_def:ty = $type_expr:ty;)? // Optional type definition
        strict: $strict:expr,
        constrained: $constrained:expr,
        basic: $basic:expr,
    ) => {
        paste::paste! {
            mod [<$stem _tests>] {
                #[allow(unused_imports)]
                use $type_path;
                $( type $type_def = $type_expr; )?

                #[test]
                #[allow(unused_variables)]
                fn test_mod_inv_basic() {
                    let a_val = 5u8;
                    let a = U256::from(a_val);
                    let modulus = U256::from(13u8);
                    let result_val = 8u8;
                    let result = U256::from(result_val);

                    crate::maybe_test!($strict, assert_eq!(super::strict_mod_inv(a, &modulus), Some(result)));
                    let a = U256::from(a_val);
                    let result = U256::from(result_val);
                    crate::maybe_test!($constrained, assert_eq!(super::constrained_mod_inv(a, &modulus), Some(result)));
                    let a = U256::from(a_val);
                    let result = U256::from(result_val);
                    crate::maybe_test!($basic, assert_eq!(super::basic_mod_inv(a, modulus), Some(result)));
                }
            }
        }
    };
}

#[cfg(test)]
mod bnum_inv_tests {
    use super::basic_mod_inv;
    use super::constrained_mod_inv;
    use super::strict_mod_inv;

    inv_test_module!(
        bnum,
        bnum::types::U256,
        strict: on,
        constrained: on,
        basic: on,
    );

    inv_test_module!(
        bnum_patched,
        bnum_patched::types::U256,
        strict: on,
        constrained: on,
        basic: on,
    );

    inv_test_module!(
        crypto_bigint,
        crypto_bigint::U256,
        strict: off, // &'a Div missing
        constrained: off, // &'a Div missing
        basic: on,
    );

    inv_test_module!(
        crypto_bigint_patched,
        crypto_bigint_patched::U256,
        strict: on,
        constrained: on,
        basic: on,
    );

    inv_test_module!(
        num_bigint,
        num_bigint::BigUint,
        type U256 = num_bigint::BigUint;
        strict: on,
        constrained: on,
        basic: off, // Copy is not implemented, heap
    );

    inv_test_module!(
        num_bigint_patched,
        num_bigint_patched::BigUint,
        type U256 = num_bigint_patched::BigUint;
        strict: on,
        constrained: on,
        basic: off, // Copy is not implemented, heap
    );

    inv_test_module!(
        ibig,
        ibig::UBig,
        type U256 = ibig::UBig;
        strict: on,
        constrained: on,
        basic: off, // Copy is not implemented, heap
    );

    inv_test_module!(
        ibig_patched,
        ibig_patched::UBig,
        type U256 = ibig_patched::UBig;
        strict: on,
        constrained: on,
        basic: off, // Copy is not implemented, heap
    );

    inv_test_module!(
        fixed_bigint,
        fixed_bigint::FixedUInt,
        type U256 = fixed_bigint::FixedUInt<u8, 4>;
        strict: on,
        constrained: on,
        basic: on,
    );
}
