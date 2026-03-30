use core::borrow::Borrow;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use crypto_bigint::{
    BoxedUint, NonZero, Odd, Resize, modular::{BoxedMontyForm, BoxedMontyParams},
};
use zeroize::Zeroize;

pub trait NumBytes: Borrow<[u8]> + Zeroize + AsRef<[u8]> {}

impl<const N: usize> NumBytes for [u8; N] {}

pub trait UnsignedModularInt: Zeroize + Clone  + Resize {
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


/// Build a Montgomery-domain value from an integer already reduced modulo `params.modulus()`
/// (same contract as [`BoxedMontyForm::new`]).
pub trait IntoMontyForm<P: ModulusParams>: Sized {
    fn from_reduced(integer: P::Modulus, params: &P) -> Self;
}

impl IntoMontyForm<BoxedMontyParams> for BoxedMontyForm {
    fn from_reduced(integer: BoxedUint, params: &BoxedMontyParams) -> Self {
        BoxedMontyForm::new(integer, params)
    }
}

pub trait PowBoundedExp<M: ModulusParams>: Sized {
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

pub trait Pow<M: ModulusParams>: Sized {
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

pub trait ModulusParams {
    type Modulus: UnsignedModularInt;
    type MontgomeryForm;
    fn modulus(&self) -> &Odd<Self::Modulus>;
    fn bits_precision(&self) -> u32;
}

impl ModulusParams for BoxedMontyParams {
    type Modulus = BoxedUint;
    type MontgomeryForm = BoxedMontyForm;
    fn modulus(&self) -> &Odd<Self::Modulus> {
        self.modulus()
    }
    fn bits_precision(&self) -> u32 {
        self.bits_precision()
    }
}

#[cfg(not(feature = "alloc"))]
pub struct NoAllocBytes(pub(crate) crypto_bigint::ByteBoxHolder<u8>);

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
