#![no_std]
#![cfg_attr(not(feature = "alloc"), allow(unused_imports))]

#![cfg_attr(not(feature = "alloc"), allow(unused))]

pub use real_crypto_bigint::{DecodeError, Gcd, Integer, NonZero, Odd};
#[cfg(feature = "rand_core")]
pub use real_crypto_bigint::RandomMod;

#[cfg(feature = "alloc")]
pub use real_crypto_bigint::{BoxedUint, Wrapping};

#[cfg(feature = "alloc")]
pub mod modular {
    pub use real_crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
}

#[cfg(not(feature = "alloc"))]
mod no_alloc {
    use core::{
        cmp::Ordering,
        ops::{
            Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div,
            DivAssign, Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign,
            Sub, SubAssign,
        },
    };

    #[cfg(feature = "rand_core")]
    use real_crypto_bigint::rand_core::CryptoRngCore;
    use real_crypto_bigint::subtle::ConstantTimeEq;
    use real_crypto_bigint::{
        AddMod, BitOps, CheckedAdd, CheckedDiv, CheckedMul, CheckedSub, DivRemLimb, Limb, Monty,
        MulMod, NegMod, NonZero, Odd, PowBoundedExp, Reciprocal, RemLimb, ShlVartime, ShrVartime,
        Square, SquareAssign, SquareRoot, SubMod, WrappingAdd, WrappingMul, WrappingNeg,
        WrappingShl, WrappingShr, WrappingSub, Zero,
        subtle::{Choice, CtOption},
        zeroize::DefaultIsZeroes,
    };

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ByteBoxHolder<T>([T; 0]);
    impl DefaultIsZeroes for ByteBoxHolder<u8> {}

    impl core::ops::Index<core::ops::RangeFrom<usize>> for ByteBoxHolder<u8> {
        type Output = [u8];

        fn index(&self, _index: core::ops::RangeFrom<usize>) -> &Self::Output {
            todo!()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Wrapping<T>(pub T);

    #[derive(Clone, PartialEq, PartialOrd, Eq, Debug, Hash, Default, Copy)]
    pub struct BoxedUint {}

    impl BoxedUint {
        pub fn bits(&self) -> u32 {
            todo!()
        }

        pub fn leading_zeros(&self) -> u32 {
            todo!()
        }

        pub fn to_be_bytes(&self) -> ByteBoxHolder<u8> {
            todo!()
        }

        pub fn bits_precision(&self) -> u32 {
            todo!()
        }

        pub fn widen(&self, _bits: u32) -> Self {
            todo!()
        }

        pub fn shorten(&self, _bits: u32) -> Self {
            todo!()
        }

        pub fn wrapping_sub(&self, _rhs: &Self) -> Self {
            todo!()
        }

        pub fn wrapping_mul(&self, _rhs: &Self) -> Self {
            todo!()
        }

        pub fn is_even(&self) -> bool {
            todo!()
        }

        pub fn zero() -> Self {
            Self {}
        }

        pub fn one() -> Self {
            todo!()
        }

        pub fn one_with_precision(_bits: u32) -> Self {
            todo!()
        }

        pub fn is_zero(&self) -> bool {
            todo!()
        }

        pub fn is_one(&self) -> bool {
            todo!()
        }

        pub fn inv_mod(&self, _modulus: &Self) -> CtOption<Self> {
            todo!()
        }

        pub fn gcd(&self, _rhs: &Self) -> Self {
            todo!()
        }

        pub fn rem_vartime(&self, _rhs: &NonZero<Self>) -> Self {
            todo!()
        }

        #[cfg(feature = "rand_core")]
        pub fn random_mod<R: CryptoRngCore + ?Sized>(
            _rng: &mut R,
            _modulus: &NonZero<Self>,
        ) -> Self {
            todo!()
        }

        pub fn square(&self) -> Self {
            todo!()
        }

        pub fn sqrt(&self) -> Self {
            todo!()
        }

        pub fn from_be_slice(
            _bytes: &[u8],
            _bits_precision: u32,
        ) -> Result<Self, real_crypto_bigint::DecodeError> {
            todo!()
        }
    }

    impl From<u64> for BoxedUint {
        fn from(_value: u64) -> Self {
            todo!()
        }
    }

    impl From<u32> for BoxedUint {
        fn from(_value: u32) -> Self {
            todo!()
        }
    }

    impl ConstantTimeEq for BoxedUint {
        fn ct_eq(&self, _other: &Self) -> Choice {
            todo!()
        }
    }

    impl real_crypto_bigint::Zero for BoxedUint {
        fn zero() -> Self {
            todo!()
        }
    }

    impl DefaultIsZeroes for BoxedUint {}

    impl PartialEq<Odd<BoxedUint>> for BoxedUint {
        fn eq(&self, _other: &Odd<BoxedUint>) -> bool {
            todo!()
        }
    }

    impl Add<BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn add(self, _rhs: BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Add<&BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn add(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Add<&BoxedUint> for &BoxedUint {
        type Output = BoxedUint;

        fn add(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Sub<BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn sub(self, _rhs: BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Sub<&BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn sub(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Sub<&BoxedUint> for &BoxedUint {
        type Output = BoxedUint;

        fn sub(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Mul<BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn mul(self, _rhs: BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Mul<&BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn mul(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Mul<&BoxedUint> for &BoxedUint {
        type Output = BoxedUint;

        fn mul(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Mul<BoxedUint> for &BoxedUint {
        type Output = BoxedUint;

        fn mul(self, _rhs: BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl MulAssign<&BoxedUint> for BoxedUint {
        fn mul_assign(&mut self, _rhs: &BoxedUint) {
            todo!()
        }
    }

    impl MulAssign<BoxedUint> for BoxedUint {
        fn mul_assign(&mut self, _rhs: BoxedUint) {
            todo!()
        }
    }

    impl Div<&BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn div(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Div<&BoxedUint> for &BoxedUint {
        type Output = BoxedUint;

        fn div(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Div<BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn div(self, _rhs: BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl Div<NonZero<BoxedUint>> for BoxedUint {
        type Output = BoxedUint;

        fn div(self, _rhs: NonZero<BoxedUint>) -> Self::Output {
            todo!()
        }
    }

    impl Div<NonZero<BoxedUint>> for &BoxedUint {
        type Output = BoxedUint;

        fn div(self, _rhs: NonZero<BoxedUint>) -> Self::Output {
            todo!()
        }
    }

    impl Rem<NonZero<BoxedUint>> for BoxedUint {
        type Output = BoxedUint;

        fn rem(self, _rhs: NonZero<BoxedUint>) -> Self::Output {
            todo!()
        }
    }

    impl Rem<NonZero<BoxedUint>> for &BoxedUint {
        type Output = BoxedUint;

        fn rem(self, _rhs: NonZero<BoxedUint>) -> Self::Output {
            todo!()
        }
    }

    impl Div<&NonZero<BoxedUint>> for BoxedUint {
        type Output = BoxedUint;

        fn div(self, _rhs: &NonZero<BoxedUint>) -> Self::Output {
            todo!()
        }
    }

    impl Div<&NonZero<BoxedUint>> for &BoxedUint {
        type Output = BoxedUint;

        fn div(self, _rhs: &NonZero<BoxedUint>) -> Self::Output {
            todo!()
        }
    }

    impl DivAssign<NonZero<BoxedUint>> for BoxedUint {
        fn div_assign(&mut self, _rhs: NonZero<BoxedUint>) {
            todo!()
        }
    }

    impl DivAssign<&NonZero<BoxedUint>> for BoxedUint {
        fn div_assign(&mut self, _rhs: &NonZero<BoxedUint>) {
            todo!()
        }
    }

    impl Rem<&NonZero<BoxedUint>> for BoxedUint {
        type Output = BoxedUint;

        fn rem(self, _rhs: &NonZero<BoxedUint>) -> Self::Output {
            todo!()
        }
    }

    impl Rem<&NonZero<BoxedUint>> for &BoxedUint {
        type Output = BoxedUint;

        fn rem(self, _rhs: &NonZero<BoxedUint>) -> Self::Output {
            todo!()
        }
    }

    impl RemAssign<NonZero<BoxedUint>> for BoxedUint {
        fn rem_assign(&mut self, _rhs: NonZero<BoxedUint>) {
            todo!()
        }
    }

    impl RemAssign<&NonZero<BoxedUint>> for BoxedUint {
        fn rem_assign(&mut self, _rhs: &NonZero<BoxedUint>) {
            todo!()
        }
    }

    impl AddAssign<BoxedUint> for BoxedUint {
        fn add_assign(&mut self, _rhs: BoxedUint) {
            todo!()
        }
    }

    impl AddAssign<&BoxedUint> for BoxedUint {
        fn add_assign(&mut self, _rhs: &BoxedUint) {
            todo!()
        }
    }

    impl SubAssign<BoxedUint> for BoxedUint {
        fn sub_assign(&mut self, _rhs: BoxedUint) {
            todo!()
        }
    }

    impl SubAssign<&BoxedUint> for BoxedUint {
        fn sub_assign(&mut self, _rhs: &BoxedUint) {
            todo!()
        }
    }

    impl BitAnd<BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn bitand(self, _rhs: BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl BitAnd<&BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn bitand(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl BitAnd<&BoxedUint> for &BoxedUint {
        type Output = BoxedUint;

        fn bitand(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl BitAndAssign for BoxedUint {
        fn bitand_assign(&mut self, _rhs: Self) {
            todo!()
        }
    }

    impl BitAndAssign<&BoxedUint> for BoxedUint {
        fn bitand_assign(&mut self, _rhs: &BoxedUint) {
            todo!()
        }
    }

    impl BitOr<BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn bitor(self, _rhs: BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl BitOr<&BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn bitor(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl BitOr<&BoxedUint> for &BoxedUint {
        type Output = BoxedUint;

        fn bitor(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl BitOrAssign for BoxedUint {
        fn bitor_assign(&mut self, _rhs: Self) {
            todo!()
        }
    }

    impl BitOrAssign<&BoxedUint> for BoxedUint {
        fn bitor_assign(&mut self, _rhs: &BoxedUint) {
            todo!()
        }
    }

    impl BitXor<BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn bitxor(self, _rhs: BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl BitXor<&BoxedUint> for BoxedUint {
        type Output = BoxedUint;

        fn bitxor(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl BitXor<&BoxedUint> for &BoxedUint {
        type Output = BoxedUint;

        fn bitxor(self, _rhs: &BoxedUint) -> Self::Output {
            todo!()
        }
    }

    impl WrappingAdd for BoxedUint {
        fn wrapping_add(&self, _v: &Self) -> Self {
            todo!()
        }
    }

    impl WrappingSub for BoxedUint {
        fn wrapping_sub(&self, _v: &Self) -> Self {
            todo!()
        }
    }

    impl WrappingMul for BoxedUint {
        fn wrapping_mul(&self, _v: &Self) -> Self {
            todo!()
        }
    }

    impl WrappingNeg for BoxedUint {
        fn wrapping_neg(&self) -> Self {
            todo!()
        }
    }

    impl WrappingShl for BoxedUint {
        fn wrapping_shl(&self, _shift: u32) -> Self {
            todo!()
        }
    }

    impl WrappingShr for BoxedUint {
        fn wrapping_shr(&self, _shift: u32) -> Self {
            todo!()
        }
    }

    impl BitXorAssign for BoxedUint {
        fn bitxor_assign(&mut self, _rhs: Self) {
            todo!()
        }
    }

    impl BitXorAssign<&BoxedUint> for BoxedUint {
        fn bitxor_assign(&mut self, _rhs: &BoxedUint) {
            todo!()
        }
    }

    impl Not for BoxedUint {
        type Output = BoxedUint;

        fn not(self) -> Self::Output {
            todo!()
        }
    }

    impl Shl<u32> for BoxedUint {
        type Output = BoxedUint;

        fn shl(self, _rhs: u32) -> Self::Output {
            todo!()
        }
    }

    impl Shl<usize> for BoxedUint {
        type Output = BoxedUint;

        fn shl(self, _rhs: usize) -> Self::Output {
            todo!()
        }
    }

    impl ShlAssign<u32> for BoxedUint {
        fn shl_assign(&mut self, _rhs: u32) {
            todo!()
        }
    }

    impl Shr<u32> for BoxedUint {
        type Output = BoxedUint;

        fn shr(self, _rhs: u32) -> Self::Output {
            todo!()
        }
    }

    impl Shr<usize> for BoxedUint {
        type Output = BoxedUint;

        fn shr(self, _rhs: usize) -> Self::Output {
            todo!()
        }
    }

    impl ShrAssign<u32> for BoxedUint {
        fn shr_assign(&mut self, _rhs: u32) {
            todo!()
        }
    }

    impl ShlVartime for BoxedUint {
        fn overflowing_shl_vartime(&self, _shift: u32) -> CtOption<Self> {
            todo!()
        }

        fn wrapping_shl_vartime(&self, _shift: u32) -> Self {
            todo!()
        }
    }

    impl ShrVartime for BoxedUint {
        fn overflowing_shr_vartime(&self, _shift: u32) -> CtOption<Self> {
            todo!()
        }

        fn wrapping_shr_vartime(&self, _shift: u32) -> Self {
            todo!()
        }
    }

    impl BitOps for BoxedUint {
        fn bits_precision(&self) -> u32 {
            todo!()
        }

        fn bytes_precision(&self) -> usize {
            todo!()
        }

        fn bit(&self, _index: u32) -> Choice {
            todo!()
        }

        fn set_bit(&mut self, _index: u32, _bit_value: Choice) {
            todo!()
        }

        fn trailing_zeros(&self) -> u32 {
            todo!()
        }

        fn trailing_ones(&self) -> u32 {
            todo!()
        }

        fn leading_zeros(&self) -> u32 {
            todo!()
        }

        fn bit_vartime(&self, _index: u32) -> bool {
            todo!()
        }

        fn bits_vartime(&self) -> u32 {
            todo!()
        }

        fn set_bit_vartime(&mut self, _index: u32, _bit_value: bool) {
            todo!()
        }

        fn trailing_zeros_vartime(&self) -> u32 {
            todo!()
        }

        fn trailing_ones_vartime(&self) -> u32 {
            todo!()
        }
    }

    impl AsRef<[Limb]> for BoxedUint {
        fn as_ref(&self) -> &[Limb] {
            todo!()
        }
    }

    impl real_crypto_bigint::subtle::ConditionallySelectable for BoxedUint {
        fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
            let _ = (a, b, choice);
            todo!()
        }
    }

    impl real_crypto_bigint::subtle::ConstantTimeLess for BoxedUint {
        fn ct_lt(&self, _other: &Self) -> Choice {
            todo!()
        }
    }

    impl real_crypto_bigint::subtle::ConstantTimeGreater for BoxedUint {
        fn ct_gt(&self, _other: &Self) -> Choice {
            todo!()
        }
    }

    impl Ord for BoxedUint {
        fn cmp(&self, _other: &Self) -> Ordering {
            todo!()
        }
    }

    impl From<u8> for BoxedUint {
        fn from(_value: u8) -> Self {
            todo!()
        }
    }

    impl From<u16> for BoxedUint {
        fn from(_value: u16) -> Self {
            todo!()
        }
    }

    impl From<Limb> for BoxedUint {
        fn from(_value: Limb) -> Self {
            todo!()
        }
    }

    impl CheckedAdd for BoxedUint {
        fn checked_add(&self, _rhs: &Self) -> CtOption<Self> {
            todo!()
        }
    }

    impl CheckedSub for BoxedUint {
        fn checked_sub(&self, _rhs: &Self) -> CtOption<Self> {
            todo!()
        }
    }

    impl CheckedMul for BoxedUint {
        fn checked_mul(&self, _rhs: &Self) -> CtOption<Self> {
            todo!()
        }
    }

    impl CheckedDiv for BoxedUint {
        fn checked_div(&self, _rhs: &Self) -> CtOption<Self> {
            todo!()
        }
    }

    impl AddMod for BoxedUint {
        type Output = BoxedUint;

        fn add_mod(&self, _rhs: &Self, _p: &Self) -> Self::Output {
            todo!()
        }
    }

    impl SubMod for BoxedUint {
        type Output = BoxedUint;

        fn sub_mod(&self, _rhs: &Self, _p: &Self) -> Self::Output {
            todo!()
        }
    }

    impl NegMod for BoxedUint {
        type Output = BoxedUint;

        fn neg_mod(&self, _p: &Self) -> Self::Output {
            todo!()
        }
    }

    impl MulMod for BoxedUint {
        type Output = BoxedUint;

        fn mul_mod(&self, _rhs: &Self, _p: &Self) -> Self::Output {
            todo!()
        }
    }

    impl RemLimb for BoxedUint {
        fn rem_limb_with_reciprocal(&self, _reciprocal: &Reciprocal) -> Limb {
            todo!()
        }
    }

    impl DivRemLimb for BoxedUint {
        fn div_rem_limb_with_reciprocal(&self, _reciprocal: &Reciprocal) -> (Self, Limb) {
            todo!()
        }
    }

    impl Square for BoxedUint {
        fn square(&self) -> Self {
            todo!()
        }
    }

    impl SquareAssign for BoxedUint {
        fn square_assign(&mut self) {
            todo!()
        }
    }

    impl SquareRoot for BoxedUint {
        fn sqrt(&self) -> Self {
            todo!()
        }

        fn sqrt_vartime(&self) -> Self {
            todo!()
        }
    }

    impl PowBoundedExp<BoxedUint> for BoxedUint {
        fn pow_bounded_exp(&self, _exponent: &BoxedUint, _exponent_bits: u32) -> Self {
            todo!()
        }
    }

    impl Neg for BoxedUint {
        type Output = BoxedUint;

        fn neg(self) -> Self::Output {
            todo!()
        }
    }

    impl Monty for BoxedUint {
        type Integer = BoxedUint;
        type Params = ();

        fn new_params_vartime(_modulus: Odd<Self::Integer>) -> Self::Params {
            todo!()
        }

        fn new(_value: Self::Integer, _params: Self::Params) -> Self {
            todo!()
        }

        fn zero(_params: Self::Params) -> Self {
            todo!()
        }

        fn one(_params: Self::Params) -> Self {
            todo!()
        }

        fn params(&self) -> &Self::Params {
            todo!()
        }

        fn as_montgomery(&self) -> &Self::Integer {
            todo!()
        }

        fn double(&self) -> Self {
            todo!()
        }

        fn div_by_2(&self) -> Self {
            todo!()
        }

        fn lincomb_vartime(_products: &[(&Self, &Self)]) -> Self {
            todo!()
        }
    }

    impl AddAssign for Wrapping<BoxedUint> {
        fn add_assign(&mut self, _rhs: Self) {
            todo!()
        }
    }

    impl MulAssign for Wrapping<BoxedUint> {
        fn mul_assign(&mut self, _rhs: Self) {
            todo!()
        }
    }

    pub mod modular {
        use core::ops::{Mul, SubAssign};

        use super::{BoxedUint, CtOption, Odd};

        #[derive(Clone, Debug)]
        pub struct BoxedMontyForm {}

        impl BoxedMontyForm {
            pub fn new(_input: BoxedUint, _params: BoxedMontyParams) -> Self {
                todo!()
            }

            pub fn bits_precision(&self) -> u32 {
                todo!()
            }

            pub fn pow(self, _exp: &BoxedUint) -> Self {
                todo!()
            }

            pub fn mul(&self, _rhs: &Self) -> Self {
                todo!()
            }

            pub fn invert(&self) -> CtOption<Self> {
                todo!()
            }

            pub fn retrieve(self) -> BoxedUint {
                todo!()
            }
        }

        impl SubAssign<&BoxedMontyForm> for BoxedMontyForm {
            fn sub_assign(&mut self, _rhs: &BoxedMontyForm) {
                todo!()
            }
        }

        impl Mul for BoxedMontyForm {
            type Output = BoxedMontyForm;

            fn mul(self, _rhs: Self) -> Self::Output {
                todo!()
            }
        }

        #[derive(Clone, Debug)]
        pub struct BoxedMontyParams {}

        impl BoxedMontyParams {
            pub fn new(_modulus: Odd<BoxedUint>) -> Self {
                todo!()
            }

            pub fn bits_precision(&self) -> u32 {
                todo!()
            }

            pub fn modulus(&self) -> &Odd<BoxedUint> {
                todo!()
            }
        }
    }


    impl real_crypto_bigint::Integer for BoxedUint {
        type Monty = Self;
    
        fn one() -> Self {
            todo!()
        }
    
        fn from_limb_like(limb: real_crypto_bigint::Limb, other: &Self) -> Self {
            todo!()
        }
    
        fn nlimbs(&self) -> usize {
            todo!()
        }
    }

    pub use modular::{BoxedMontyForm, BoxedMontyParams};
}

#[cfg(not(feature = "alloc"))]
pub use no_alloc::{BoxedUint, ByteBoxHolder, Wrapping, modular};
