use core::borrow::Borrow;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use crypto_bigint::{NonZero as CryptoNonZero, Odd as CryptoOdd};
#[cfg(feature = "alloc")]
use crypto_bigint::{
    BoxedUint,
    Resize as CryptoResize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use zeroize::Zeroize;

pub trait NumBytes: Borrow<[u8]> + Zeroize + AsRef<[u8]> {}

impl<const N: usize> NumBytes for [u8; N] {}

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

pub trait UnsignedModularInt: Zeroize + Clone + IntegerResize<Output = Self> {
    type Bytes: NumBytes;
    fn leading_zeros(&self) -> u32;
    fn to_be_bytes(&self) -> Self::Bytes;
    fn rem_vartime(&self, modulus: &NonZero<Self>) -> Self;
    fn as_nz_ref(&self) -> NonZero<Self>;
    fn bits(&self) -> u32;
    fn bits_precision(&self) -> u32;
    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]>;
}

pub trait FromBeBytes: UnsignedModularInt {
    fn from_be_bytes_vartime(bytes: &[u8]) -> Self;
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


/// Build a Montgomery-domain value from an integer already reduced modulo `params.modulus()`.
pub trait IntoMontyForm<P: ModulusParams>: Sized {
    fn from_reduced(integer: P::Modulus, params: &P) -> Self;
}

#[cfg(feature = "alloc")]
impl IntoMontyForm<BoxedMontyParams> for BoxedMontyForm {
    fn from_reduced(integer: BoxedUint, params: &BoxedMontyParams) -> Self {
        BoxedMontyForm::new(integer, params)
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
    fn retrieve(&self) -> M::Modulus;
}

#[cfg(feature = "alloc")]
impl Pow<BoxedMontyParams> for BoxedMontyForm {
    fn pow(&self, exp: &BoxedUint) -> Self {
        self.clone().pow(exp)
    }

    fn retrieve(&self) -> BoxedUint {
        self.clone().retrieve()
    }
}

pub trait ModulusParams {
    type Modulus: UnsignedModularInt;
    type MontgomeryForm;
    fn modulus(&self) -> &Odd<Self::Modulus>;
    fn bits_precision(&self) -> u32;
}

#[cfg(feature = "alloc")]
impl ModulusParams for BoxedMontyParams {
    type Modulus = BoxedUint;
    type MontgomeryForm = BoxedMontyForm;
    fn modulus(&self) -> &Odd<Self::Modulus> {
        // Safety: both wrappers are transparent newtypes over the same `BoxedUint`.
        unsafe { &*(self.modulus() as *const CryptoOdd<Self::Modulus> as *const Odd<Self::Modulus>) }
    }
    fn bits_precision(&self) -> u32 {
        self.bits_precision()
    }
}

#[cfg(feature = "alloc")]
impl NumBytes for alloc::boxed::Box<[u8]> {}

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
        self.rem_vartime(&CryptoNonZero::new(modulus.as_ref().clone()).expect("Value is non-zero"))
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
impl FromBeBytes for BoxedUint {
    fn from_be_bytes_vartime(bytes: &[u8]) -> Self {
        BoxedUint::from_be_slice_vartime(bytes)
    }
}
