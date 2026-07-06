// TODO: document the public surface once the trait shape settles.
#![allow(missing_docs)]

use core::borrow::Borrow;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use const_num_traits::PrimBits;
#[cfg(not(feature = "modmath"))]
use const_num_traits::PrimInt;
use const_num_traits::{FromBytes as NumFromBytes, ToBytes as NumToBytes, Zero};
#[cfg(feature = "alloc")]
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, Resize as CryptoResize,
};
#[cfg(feature = "alloc")]
use crypto_bigint::{NonZero as CryptoNonZero, Odd as CryptoOdd};
use zeroize::Zeroize;

use crate::errors::{Error, Result};

pub trait NumBytes: Borrow<[u8]> + AsRef<[u8]> {}

impl<T> NumBytes for T where T: Borrow<[u8]> + AsRef<[u8]> {}

#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonZero<T>(T);

#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Odd<T>(T);

pub trait IntegerResize: Sized {
    type Output;

    fn resize_unchecked(self, at_least_bits_precision: u32) -> Self::Output;
    fn try_resize(self, at_least_bits_precision: u32) -> Option<Self::Output>;
}

pub trait FixedWidthUnsignedInt: Zeroize + Clone + Copy {
    type Bytes: NumBytes + Default + AsMut<[u8]>;

    fn leading_zeros(&self) -> u32;
    fn to_be_bytes(&self) -> Self::Bytes;
    fn try_from_be_bytes_vartime(bytes: &[u8]) -> Result<Self>;
    fn bits_precision(&self) -> u32;
}

#[cfg(feature = "modmath")]
impl<T> FixedWidthUnsignedInt for T
where
    T: Zeroize + Clone + Copy + PrimBits + Zero + NumToBytes + NumFromBytes,
    T: NumToBytes<Bytes = <T as NumFromBytes>::Bytes>,
    <T as NumToBytes>::Bytes: NumBytes + Default + AsMut<[u8]>,
{
    type Bytes = <T as NumToBytes>::Bytes;

    fn leading_zeros(&self) -> u32 {
        PrimBits::leading_zeros(*self)
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        NumToBytes::to_be_bytes(*self)
    }

    fn try_from_be_bytes_vartime(bytes: &[u8]) -> Result<Self> {
        let mut repr = <T as NumFromBytes>::Bytes::default();
        let out = repr.as_mut();
        let out_len = out.len();
        if bytes.len() > out_len {
            return Err(Error::InvalidArguments);
        }
        out[out_len - bytes.len()..].copy_from_slice(bytes);
        Ok(NumFromBytes::from_be_bytes(&repr))
    }

    fn bits_precision(&self) -> u32 {
        PrimBits::count_zeros(<T as Zero>::zero())
    }
}

#[cfg(not(feature = "modmath"))]
impl<T> FixedWidthUnsignedInt for T
where
    T: Zeroize + Clone + Copy + PrimInt + NumToBytes + NumFromBytes,
    T: NumToBytes<Bytes = <T as NumFromBytes>::Bytes>,
    <T as NumToBytes>::Bytes: NumBytes + Default + AsMut<[u8]>,
{
    type Bytes = <T as NumToBytes>::Bytes;

    fn leading_zeros(&self) -> u32 {
        PrimBits::leading_zeros(*self)
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        NumToBytes::to_be_bytes(*self)
    }

    fn try_from_be_bytes_vartime(bytes: &[u8]) -> Result<Self> {
        let mut repr = <T as NumFromBytes>::Bytes::default();
        let out = repr.as_mut();
        let out_len = out.len();
        if bytes.len() > out_len {
            return Err(Error::InvalidArguments);
        }
        out[out_len - bytes.len()..].copy_from_slice(bytes);
        Ok(NumFromBytes::from_be_bytes(&repr))
    }

    fn bits_precision(&self) -> u32 {
        <T as Zero>::zero().count_zeros()
    }
}

#[cfg(not(feature = "alloc"))]
impl<T> IntegerResize for T
where
    T: FixedWidthUnsignedInt,
{
    type Output = Self;

    fn resize_unchecked(self, _at_least_bits_precision: u32) -> Self::Output {
        self
    }

    fn try_resize(self, at_least_bits_precision: u32) -> Option<Self::Output> {
        // Mirrors `crypto_bigint::Resize::try_resize`: returns `Some` iff
        // the actual value fits in `at_least_bits_precision` bits. T is
        // fixed-width and `resize_unchecked` is a no-op, but the check
        // still needs to reject values that wouldn't survive a narrower
        // precision.
        let value_bits = self.bits_precision() - self.leading_zeros();
        if value_bits <= at_least_bits_precision {
            Some(self)
        } else {
            None
        }
    }
}

#[cfg(not(feature = "alloc"))]
impl<T> UnsignedModularInt for T
where
    T: FixedWidthUnsignedInt + PartialOrd,
{
    type Bytes = <T as FixedWidthUnsignedInt>::Bytes;

    fn leading_zeros(&self) -> u32 {
        FixedWidthUnsignedInt::leading_zeros(self)
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        FixedWidthUnsignedInt::to_be_bytes(self)
    }

    fn as_nz_ref(&self) -> NonZero<Self> {
        NonZero::new(*self).expect("value is non-zero")
    }

    fn bits(&self) -> u32 {
        self.bits_precision() - self.leading_zeros()
    }

    fn bits_precision(&self) -> u32 {
        FixedWidthUnsignedInt::bits_precision(self)
    }

    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        unreachable!("alloc-gated")
    }
}

#[cfg(not(feature = "alloc"))]
impl<T> TryFromBeBytes for T
where
    T: FixedWidthUnsignedInt,
{
    fn try_from_be_bytes_vartime(bytes: &[u8]) -> Result<Self> {
        FixedWidthUnsignedInt::try_from_be_bytes_vartime(bytes)
    }
}

pub trait TryFromBeBytes: Sized {
    fn try_from_be_bytes_vartime(bytes: &[u8]) -> Result<Self>;
}

pub trait UnsignedModularInt:
    Zeroize + Clone + PartialOrd + IntegerResize<Output = Self> + TryFromBeBytes
{
    type Bytes: NumBytes + AsMut<[u8]>;
    fn leading_zeros(&self) -> u32;
    fn to_be_bytes(&self) -> Self::Bytes;
    fn as_nz_ref(&self) -> NonZero<Self>;
    fn bits(&self) -> u32;
    fn bits_precision(&self) -> u32;
    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]>;
}

impl<T> NonZero<T>
where
    T: UnsignedModularInt,
{
    pub fn new(value: T) -> Option<Self> {
        if value.bits() == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub fn get(self) -> T {
        self.0
    }

    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> &T {
        &self.0
    }

    pub fn bits(&self) -> u32 {
        self.0.bits()
    }

    pub fn bits_precision(&self) -> u32 {
        self.0.bits_precision()
    }

    pub fn to_be_bytes(&self) -> T::Bytes {
        self.0.to_be_bytes()
    }

    #[cfg(feature = "alloc")]
    pub fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        self.0.to_be_bytes_trimmed_vartime()
    }
}

impl<T> Odd<T>
where
    T: UnsignedModularInt,
{
    pub fn new(value: T) -> Option<Self> {
        let non_zero = NonZero::new(value)?;
        let bytes = non_zero.as_ref().to_be_bytes();
        let bytes = bytes.as_ref();
        let is_odd = bytes.last().map(|byte| byte & 1 == 1).unwrap_or(false);
        if is_odd {
            Some(Self(non_zero.get()))
        } else {
            None
        }
    }

    pub fn get(self) -> T {
        self.0
    }

    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> &T {
        &self.0
    }

    pub fn as_nz_ref(&self) -> NonZero<T> {
        NonZero::new(self.0.clone()).expect("odd values are non-zero")
    }

    pub fn bits_precision(&self) -> u32 {
        self.0.bits_precision()
    }
}

/// Build a Montgomery-domain value.
///
/// Two constructors with **different input contracts**:
///
/// - [`from_reduced`](Self::from_reduced) — caller guarantees `integer <
///   params.modulus()`. Implementations may rely on this; no reduction is
///   performed. Use this when you already know the value is reduced.
/// - [`from_value`](Self::from_value) — accepts any `integer` in
///   `[0, 2^bits_precision)`. Implementations MUST handle the unreduced
///   case (either by reducing internally or by using a Montgomery primitive
///   that tolerates unreduced inputs, e.g. CIOS with `raw * R²`).
///
/// No default `from_value` is provided on purpose. Forwarding to
/// `from_reduced` would silently produce wrong results for unreduced
/// inputs on backends that don't tolerate them — the trait makes this
/// distinction explicit so each implementor confronts it.
pub trait IntoMontyForm<P: ModulusParams>: Sized {
    /// Build from an integer already reduced modulo `params.modulus()`.
    fn from_reduced(integer: P::Modulus, params: &P) -> Self;

    /// Build from any integer in `[0, 2^bits_precision)`, handling
    /// reduction internally if needed.
    fn from_value(integer: P::Modulus, params: &P) -> Self;
}

#[cfg(feature = "alloc")]
impl IntoMontyForm<BoxedMontyParams> for BoxedMontyForm {
    fn from_reduced(integer: BoxedUint, params: &BoxedMontyParams) -> Self {
        BoxedMontyForm::new(integer, params)
    }

    fn from_value(integer: BoxedUint, params: &BoxedMontyParams) -> Self {
        let modulus =
            CryptoNonZero::new(params.modulus().as_ref().clone()).expect("modulus is non-zero");
        let reduced = integer.rem_vartime(&modulus);
        Self::from_reduced(reduced, params)
    }
}

pub trait PowBoundedExp<M: ModulusParams>: Sized {
    fn pow_bounded_exp(&self, exp: &M::Modulus, exp_bits: u32) -> Self;
    fn retrieve(&self) -> M::Modulus;
}

#[cfg(feature = "alloc")]
impl PowBoundedExp<BoxedMontyParams> for BoxedMontyForm {
    fn pow_bounded_exp(&self, exp: &BoxedUint, exp_bits: u32) -> Self {
        self.clone().pow_bounded_exp(exp, exp_bits)
    }

    fn retrieve(&self) -> BoxedUint {
        self.clone().retrieve()
    }
}

pub trait Pow<M: ModulusParams>: Sized {
    fn pow(&self, exp: &M::Modulus) -> Self;
}

#[cfg(feature = "alloc")]
impl Pow<BoxedMontyParams> for BoxedMontyForm {
    fn pow(&self, exp: &BoxedUint) -> Self {
        self.clone().pow(exp)
    }
}

pub trait ModulusParams: Sized {
    type Modulus: UnsignedModularInt;
    type MontgomeryForm: IntoMontyForm<Self> + PowBoundedExp<Self>;
    fn modulus(&self) -> &Odd<Self::Modulus>;
    fn bits_precision(&self) -> u32;
}

#[cfg(feature = "alloc")]
impl ModulusParams for BoxedMontyParams {
    type Modulus = BoxedUint;
    type MontgomeryForm = BoxedMontyForm;
    fn modulus(&self) -> &Odd<Self::Modulus> {
        // Our `Odd<T>` is `#[repr(transparent)]` over `T`. `crypto_bigint::Odd<T>`
        // is a single-field tuple struct around `T`, not formally
        // `#[repr(transparent)]` — verify layout at compile time so a future
        // crypto_bigint version that changes representation fails to build
        // instead of producing silent UB.
        const _: () = assert!(
            core::mem::size_of::<CryptoOdd<BoxedUint>>() == core::mem::size_of::<Odd<BoxedUint>>()
        );
        const _: () = assert!(
            core::mem::align_of::<CryptoOdd<BoxedUint>>()
                == core::mem::align_of::<Odd<BoxedUint>>()
        );
        unsafe {
            &*(self.modulus() as *const CryptoOdd<Self::Modulus> as *const Odd<Self::Modulus>)
        }
    }
    fn bits_precision(&self) -> u32 {
        self.bits_precision()
    }
}

#[cfg(feature = "alloc")]
impl IntegerResize for BoxedUint {
    type Output = Self;

    fn resize_unchecked(self, at_least_bits_precision: u32) -> Self::Output {
        CryptoResize::resize_unchecked(self, at_least_bits_precision)
    }

    fn try_resize(self, at_least_bits_precision: u32) -> Option<Self::Output> {
        CryptoResize::try_resize(self, at_least_bits_precision)
    }
}

#[cfg(feature = "alloc")]
impl UnsignedModularInt for BoxedUint {
    type Bytes = alloc::boxed::Box<[u8]>;

    fn leading_zeros(&self) -> u32 {
        self.leading_zeros()
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        self.to_be_bytes()
    }
    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        self.to_be_bytes_trimmed_vartime()
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

#[cfg(feature = "alloc")]
impl TryFromBeBytes for BoxedUint {
    fn try_from_be_bytes_vartime(bytes: &[u8]) -> Result<Self> {
        Ok(BoxedUint::from_be_slice_vartime(bytes))
    }
}
