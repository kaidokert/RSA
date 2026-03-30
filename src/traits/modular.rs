use core::borrow::Borrow;

use core::ops::Rem;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use crypto_bigint::{
    BoxedUint, Choice, CtAssign, CtEq, NonZero, Odd, One, Resize, Zero, modular::{BoxedMontyForm, BoxedMontyParams},
};
use zeroize::Zeroize;

pub trait NumBytes: Borrow<[u8]> + Zeroize + AsRef<[u8]> {}

impl NumBytes for [u8; 1] {}

pub trait UnsignedModularInt: Zeroize + Clone  + Resize {
    type Bytes: NumBytes;
    fn leading_zeros(&self) -> u32;
    fn to_be_bytes(&self) -> Self::Bytes;
    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]>;
    fn rem_vartime(&self, modulus: &NonZero<Self>) -> Self;
    fn as_nz_ref(&self) -> NonZero<Self>;
    fn bits(&self) -> u32;
    fn bits_precision(&self) -> u32;
    //fn resize_unchecked(&self, new_len: usize) -> Self;
}


/// Build a Montgomery-domain value from an integer already reduced modulo `params.modulus()`
/// (same contract as [`BoxedMontyForm::new`]).
pub trait IntoMontyForm<P: MParam>: Sized {
    fn from_reduced(integer: P::Modulus, params: &P) -> Self;
}

impl IntoMontyForm<BoxedMontyParams> for BoxedMontyForm {
    fn from_reduced(integer: BoxedUint, params: &BoxedMontyParams) -> Self {
        BoxedMontyForm::new(integer, params)
    }
}

pub trait PowBoundedExp<M: MParam>: Sized {
    fn pow_bounded_exp(&self, exp: &M::Modulus, exp_bits: u32) -> Self;
    fn retrieve(&self) -> M::Modulus;
}

impl PowBoundedExp<BoxedMontyParams> for BoxedMontyForm {
    fn pow_bounded_exp(&self, exp: &BoxedUint, exp_bits: u32) -> Self {
        self.clone().pow_bounded_exp(exp, exp_bits)
    }

    fn retrieve(&self) -> BoxedUint {
        self.clone().retrieve()
    }
}

pub trait Pow<M: MParam>: Sized {
    fn pow(&self, exp: &M::Modulus) -> Self;
    fn retrieve(&self) -> M::Modulus;
}

impl Pow<BoxedMontyParams> for BoxedMontyForm {
    fn pow(&self, exp: &BoxedUint) -> Self {
        self.clone().pow(exp)
    }

    fn retrieve(&self) -> BoxedUint {
        self.clone().retrieve()
    }
}

pub trait MParam {
    type Modulus: UnsignedModularInt;
    type Form;
    fn modulus(&self) -> &Odd<Self::Modulus>;
    fn bits_precision(&self) -> u32;
}

impl MParam for BoxedMontyParams {
    type Modulus = BoxedUint;
    type Form = BoxedMontyForm;
    fn modulus(&self) -> &Odd<Self::Modulus> {
        self.modulus()
    }
    fn bits_precision(&self) -> u32 {
        self.bits_precision()
    }
}

#[cfg(not(feature = "alloc"))]
pub struct NoAllocBytes(pub(crate) crypto_bigint::ByteBoxHolder<u8>);

#[derive(Clone, Copy)]
pub struct  WrapU8(u8);

impl From<u8> for WrapU8 {
    fn from(value: u8) -> Self {
        WrapU8(value)
    }
}

impl Resize for WrapU8 {
    type Output = Self;
    
    fn resize_unchecked(self, new_len: u32) -> Self {
        if new_len == 0 {
            WrapU8(0)
        } else {
            self.clone()
        }
    }
    
    fn try_resize(self, at_least_bits_precision: u32) -> Option<Self::Output> {
        Some(self.resize_unchecked(at_least_bits_precision))
    }
}
impl Zeroize for WrapU8 {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

impl CtEq for WrapU8 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl CtAssign for WrapU8 {
    fn ct_assign(&mut self, src: &Self, choice: Choice) {
        self.0.ct_assign(&src.0, choice);
    }
}

impl Zero for WrapU8 {
    fn zero() -> Self {
        WrapU8(0)
    }
}

impl One for WrapU8 {
    fn one() -> Self {
        WrapU8(1)
    }
}

impl Rem for WrapU8 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        WrapU8(self.0 % rhs.0)
    }
}

impl UnsignedModularInt for WrapU8 {
    type Bytes = [u8; 1];

    fn leading_zeros(&self) -> u32 {
        u8::leading_zeros(self.0)
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        u8::to_be_bytes(self.0)
    }
    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        alloc::vec![self.0].into_boxed_slice()
    }
    fn rem_vartime(&self, modulus: &NonZero<Self>) -> Self {
        WrapU8((*self).0 % (*modulus).0)
    }
    fn as_nz_ref(&self) -> NonZero<Self> {
        NonZero::new(self.clone()).expect("Value is non-zero")
    }
    fn bits(&self) -> u32 {
        8
    }
    fn bits_precision(&self) -> u32 {
        8
    }
}

#[cfg(feature = "alloc")]
impl NumBytes for alloc::boxed::Box<[u8]> {}

#[cfg(feature = "alloc")]
impl UnsignedModularInt for BoxedUint {
    type Bytes = alloc::boxed::Box<[u8]>;

    fn leading_zeros(&self) -> u32 {
        self.leading_zeros()
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        self.as_words()
            .iter()
            .rev()
            .flat_map(|word| word.to_be_bytes())
            .collect::<alloc::vec::Vec<u8>>()
            .into_boxed_slice()
    }
    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        self.to_be_bytes_trimmed_vartime()
    }
    fn rem_vartime(&self, modulus: &NonZero<Self>) -> Self {
        self.rem_vartime(modulus)
    }
    fn as_nz_ref(&self) -> NonZero<Self> {
        NonZero::new(self.clone()).expect("Value is non-zero")
    }
    fn bits(&self) -> u32 {
        self.bits()
    }
    fn bits_precision(&self) -> u32 {
        self.bits_precision()
    }
}

#[cfg(not(feature = "alloc"))]
impl Borrow<[u8]> for NoAllocBytes {
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

#[cfg(not(feature = "alloc"))]
impl AsRef<[u8]> for NoAllocBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0[0..]
    }
}

#[cfg(not(feature = "alloc"))]
impl Zeroize for NoAllocBytes {
    fn zeroize(&mut self) {}
}

#[cfg(not(feature = "alloc"))]
impl NumBytes for NoAllocBytes {}

#[cfg(not(feature = "alloc"))]
impl UnsignedModularInt for BoxedUint {
    type Bytes = NoAllocBytes;

    fn leading_zeros(&self) -> u32 {
        self.leading_zeros()
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        NoAllocBytes(self.to_be_bytes())
    }

    fn rem_vartime(&self, modulus: &NonZero<Self>) -> Self {
        self.rem_vartime(modulus)
    }

    fn as_nz_ref(&self) -> NonZero<Self> {
        NonZero::new(self.clone()).expect("Value is non-zero")
    }
    fn bits(&self) -> u32 {
        self.bits()
    }
    fn bits_precision(&self) -> u32 {
        self.bits_precision()
    }
}
