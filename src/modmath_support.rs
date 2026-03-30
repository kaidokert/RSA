//! Experimental `modmath` backend adapters for generic RSA verification paths.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec;
use core::ops::{Add, BitAnd, Mul, Rem, RemAssign, Shr, ShrAssign, Sub};

use crypto_bigint::{Choice, CtAssign, CtEq, NonZero, Odd, One, Resize, Zero};
use fixed_bigint::FixedUInt;
use fixed_bigint::num_traits;
use fixed_bigint::num_traits::ops::overflowing::{OverflowingAdd, OverflowingMul, OverflowingSub};
use fixed_bigint::num_traits::PrimInt;
use modmath::basic_mod_exp;
use num_traits::ops::wrapping::{WrappingAdd, WrappingSub};
use zeroize::Zeroize;

use crate::{
    algorithms::rsa::rsa_encrypt,
    key::RsaPublicKey,
    traits::modular::{IntoMontyForm, MParam, Pow, PowBoundedExp, UnsignedModularInt},
    Error, Result,
};

/// A fixed-size integer wrapper that satisfies the current RSA abstraction layer
/// while delegating modular exponentiation to `modmath`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ModMathFixedUint<const N: usize>(pub FixedUInt<u8, N>);

impl<const N: usize> ModMathFixedUint<N> {
    /// Build a fixed-width integer from big-endian bytes.
    pub fn from_be_slice(bytes: &[u8]) -> Self {
        Self(FixedUInt::from_be_bytes(bytes))
    }

    fn is_odd(&self) -> bool {
        self.0.words()[0] & 1 == 1
    }
}

impl<const N: usize> From<u8> for ModMathFixedUint<N> {
    fn from(value: u8) -> Self {
        let mut bytes = [0u8; N];
        if N > 0 {
            bytes[N - 1] = value;
        }
        Self(FixedUInt::from_be_bytes(&bytes))
    }
}

impl<const N: usize> Zeroize for ModMathFixedUint<N> {
    fn zeroize(&mut self) {
        self.0 = FixedUInt::new();
    }
}

impl<const N: usize> CtEq for ModMathFixedUint<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self == other) as u8)
    }
}

impl<const N: usize> CtAssign for ModMathFixedUint<N> {
    fn ct_assign(&mut self, src: &Self, choice: Choice) {
        if bool::from(choice) {
            *self = *src;
        }
    }
}

impl<const N: usize> Zero for ModMathFixedUint<N> {
    fn zero() -> Self {
        Self(FixedUInt::new())
    }
}

impl<const N: usize> One for ModMathFixedUint<N> {
    fn one() -> Self {
        Self::from(1u8)
    }
}

impl<const N: usize> num_traits::Zero for ModMathFixedUint<N> {
    fn zero() -> Self {
        Zero::zero()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl<const N: usize> num_traits::One for ModMathFixedUint<N> {
    fn one() -> Self {
        One::one()
    }
}

impl<const N: usize> Add for ModMathFixedUint<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.overflowing_add(&rhs.0).0)
    }
}

impl<const N: usize> Sub for ModMathFixedUint<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.overflowing_sub(&rhs.0).0)
    }
}

impl<const N: usize> Mul for ModMathFixedUint<N> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.overflowing_mul(&rhs.0).0)
    }
}

impl<const N: usize> BitAnd for ModMathFixedUint<N> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl<const N: usize> Rem for ModMathFixedUint<N> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self(self.0 % rhs.0)
    }
}

impl<const N: usize> RemAssign for ModMathFixedUint<N> {
    fn rem_assign(&mut self, rhs: Self) {
        self.0 %= rhs.0;
    }
}

impl<const N: usize> Shr<usize> for ModMathFixedUint<N> {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        Self(self.0 >> rhs)
    }
}

impl<const N: usize> ShrAssign<usize> for ModMathFixedUint<N> {
    fn shr_assign(&mut self, rhs: usize) {
        self.0 >>= rhs;
    }
}

impl<const N: usize> WrappingAdd for ModMathFixedUint<N> {
    fn wrapping_add(&self, v: &Self) -> Self {
        *self + *v
    }
}

impl<const N: usize> WrappingSub for ModMathFixedUint<N> {
    fn wrapping_sub(&self, v: &Self) -> Self {
        *self - *v
    }
}

impl<const N: usize> Resize for ModMathFixedUint<N> {
    type Output = Self;

    fn resize_unchecked(self, _at_least_bits_precision: u32) -> Self::Output {
        self
    }

    fn try_resize(self, at_least_bits_precision: u32) -> Option<Self::Output> {
        if at_least_bits_precision >= self.bits_precision() {
            Some(self)
        } else {
            None
        }
    }
}

impl<const N: usize> UnsignedModularInt for ModMathFixedUint<N> {
    type Bytes = [u8; N];

    fn leading_zeros(&self) -> u32 {
        self.0.leading_zeros()
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        let mut bytes = [0u8; N];
        let _ = self.0.to_be_bytes(&mut bytes).expect("fixed buffer matches precision");
        bytes
    }

    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> alloc::boxed::Box<[u8]> {
        let bytes = self.to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len().saturating_sub(1));
        bytes[first_non_zero..].to_vec().into_boxed_slice()
    }

    fn rem_vartime(&self, modulus: &NonZero<Self>) -> Self {
        *self % *modulus.as_ref()
    }

    fn as_nz_ref(&self) -> NonZero<Self> {
        NonZero::new(*self).expect("value is non-zero")
    }

    fn bits(&self) -> u32 {
        self.0.bit_length()
    }

    fn bits_precision(&self) -> u32 {
        N as u32 * 8
    }
}

#[derive(Clone, Debug)]
pub struct ModMathParams<const N: usize> {
    modulus: ModMathFixedUint<N>,
}

impl<const N: usize> ModMathParams<N> {
    /// Create modular arithmetic parameters for an odd, non-zero modulus.
    pub fn new(modulus: ModMathFixedUint<N>) -> Result<Self> {
        if bool::from(modulus.ct_eq(&ModMathFixedUint::zero())) {
            return Err(Error::InvalidModulus);
        }

        if !modulus.is_odd() {
            return Err(Error::InvalidModulus);
        }

        Ok(Self { modulus })
    }
}

/// Construct a public key backed by the `modmath` adapter from big-endian
/// modulus bytes and a small public exponent.
pub fn public_key_from_be_bytes<const N: usize>(
    modulus: &[u8; N],
    exponent: u8,
) -> Result<RsaPublicKey<ModMathFixedUint<N>, ModMathParams<N>>> {
    let n = ModMathFixedUint::<N>::from_be_slice(modulus);
    let e = ModMathFixedUint::<N>::from(exponent);
    RsaPublicKey::from_components(n, e, ModMathParams::new(n)?)
}

/// Apply the raw RSA public operation to a fixed-width block.
///
/// For signature use-cases this effectively "decrypts" the signature into its
/// encoded message representative.
pub fn rsa_decrypt<const N: usize>(
    key: &RsaPublicKey<ModMathFixedUint<N>, ModMathParams<N>>,
    input: &[u8; N],
) -> Result<[u8; N]> {
    let block = ModMathFixedUint::<N>::from_be_slice(input);
    Ok(rsa_encrypt(key, &block)?.to_be_bytes())
}

/// Verify a PKCS#1 v1.5 SHA-1 signature using a precomputed SHA-1 digest.
pub fn verify_pkcs1v15_sha1_prehash<const N: usize>(
    key: &RsaPublicKey<ModMathFixedUint<N>, ModMathParams<N>>,
    prehash: &[u8],
    signature: &[u8; N],
) -> Result<()> {
    const SHA1_PREFIX: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
        0x14,
    ];
    let sig = ModMathFixedUint::<N>::from_be_slice(signature);
    let mut em_storage = [0u8; N];

    crate::pkcs1v15::verify_noalloc_generic(key, &SHA1_PREFIX, prehash, &sig, &mut em_storage)
}

/// A `modmath` adapter backed by `fixed_bigint::FixedUInt<u32, N>`.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ModMathFixedUint32<const N: usize>(pub FixedUInt<u32, N>);

#[cfg(feature = "alloc")]
impl<const N: usize> ModMathFixedUint32<N> {
    /// Build a fixed-width integer from big-endian bytes.
    pub fn from_be_slice(bytes: &[u8]) -> Self {
        Self(FixedUInt::from_be_bytes(bytes))
    }

    fn is_odd(&self) -> bool {
        self.0.words()[0] & 1 == 1
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> From<u8> for ModMathFixedUint32<N> {
    fn from(value: u8) -> Self {
        let mut bytes = vec![0u8; 4 * N];
        if N > 0 {
            bytes[(4 * N) - 1] = value;
        }
        Self(FixedUInt::from_be_bytes(&bytes))
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Zeroize for ModMathFixedUint32<N> {
    fn zeroize(&mut self) {
        self.0 = FixedUInt::new();
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> CtEq for ModMathFixedUint32<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self == other) as u8)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> CtAssign for ModMathFixedUint32<N> {
    fn ct_assign(&mut self, src: &Self, choice: Choice) {
        if bool::from(choice) {
            *self = *src;
        }
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Zero for ModMathFixedUint32<N> {
    fn zero() -> Self {
        Self(FixedUInt::new())
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> One for ModMathFixedUint32<N> {
    fn one() -> Self {
        Self::from(1u8)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> num_traits::Zero for ModMathFixedUint32<N> {
    fn zero() -> Self {
        Zero::zero()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> num_traits::One for ModMathFixedUint32<N> {
    fn one() -> Self {
        One::one()
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Add for ModMathFixedUint32<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.overflowing_add(&rhs.0).0)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Sub for ModMathFixedUint32<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.overflowing_sub(&rhs.0).0)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Mul for ModMathFixedUint32<N> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.overflowing_mul(&rhs.0).0)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> BitAnd for ModMathFixedUint32<N> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Rem for ModMathFixedUint32<N> {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self(self.0 % rhs.0)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> RemAssign for ModMathFixedUint32<N> {
    fn rem_assign(&mut self, rhs: Self) {
        self.0 %= rhs.0;
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Shr<usize> for ModMathFixedUint32<N> {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        Self(self.0 >> rhs)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> ShrAssign<usize> for ModMathFixedUint32<N> {
    fn shr_assign(&mut self, rhs: usize) {
        self.0 >>= rhs;
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> WrappingAdd for ModMathFixedUint32<N> {
    fn wrapping_add(&self, v: &Self) -> Self {
        *self + *v
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> WrappingSub for ModMathFixedUint32<N> {
    fn wrapping_sub(&self, v: &Self) -> Self {
        *self - *v
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Resize for ModMathFixedUint32<N> {
    type Output = Self;

    fn resize_unchecked(self, _at_least_bits_precision: u32) -> Self::Output {
        self
    }

    fn try_resize(self, at_least_bits_precision: u32) -> Option<Self::Output> {
        if at_least_bits_precision >= self.bits_precision() {
            Some(self)
        } else {
            None
        }
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> UnsignedModularInt for ModMathFixedUint32<N> {
    type Bytes = Box<[u8]>;

    fn leading_zeros(&self) -> u32 {
        self.0.leading_zeros()
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        let mut bytes = vec![0u8; 4 * N];
        let _ = self.0.to_be_bytes(&mut bytes).expect("fixed buffer matches precision");
        bytes.into_boxed_slice()
    }

    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        let bytes = self.to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len().saturating_sub(1));
        bytes[first_non_zero..].to_vec().into_boxed_slice()
    }

    fn rem_vartime(&self, modulus: &NonZero<Self>) -> Self {
        *self % *modulus.as_ref()
    }

    fn as_nz_ref(&self) -> NonZero<Self> {
        NonZero::new(*self).expect("value is non-zero")
    }

    fn bits(&self) -> u32 {
        self.0.bit_length()
    }

    fn bits_precision(&self) -> u32 {
        (4 * N) as u32 * 8
    }
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct ModMathParams32<const N: usize> {
    modulus: ModMathFixedUint32<N>,
}

#[cfg(feature = "alloc")]
impl<const N: usize> ModMathParams32<N> {
    /// Create modular arithmetic parameters for an odd, non-zero modulus.
    pub fn new(modulus: ModMathFixedUint32<N>) -> Result<Self> {
        if bool::from(modulus.ct_eq(&ModMathFixedUint32::zero())) {
            return Err(Error::InvalidModulus);
        }

        if !modulus.is_odd() {
            return Err(Error::InvalidModulus);
        }

        Ok(Self { modulus })
    }
}

/// Construct a public key backed by the `modmath` adapter from big-endian
/// modulus bytes and a small public exponent, using `FixedUInt<u32, N>`.
#[cfg(feature = "alloc")]
pub fn public_key_from_be_bytes_u32<const N: usize>(
    modulus: &[u8],
    exponent: u8,
) -> Result<RsaPublicKey<ModMathFixedUint32<N>, ModMathParams32<N>>> {
    let n = ModMathFixedUint32::<N>::from_be_slice(modulus);
    let e = ModMathFixedUint32::<N>::from(exponent);
    RsaPublicKey::from_components(n, e, ModMathParams32::new(n)?)
}

/// Verify a PKCS#1 v1.5 SHA-1 signature using a `FixedUInt<u32, N>` backend.
#[cfg(feature = "alloc")]
pub fn verify_pkcs1v15_sha1_prehash_u32<const N: usize>(
    key: &RsaPublicKey<ModMathFixedUint32<N>, ModMathParams32<N>>,
    prehash: &[u8],
    signature: &[u8],
) -> Result<()> {
    const SHA1_PREFIX: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
        0x14,
    ];
    let sig = ModMathFixedUint32::<N>::from_be_slice(signature);
    let mut em_storage = vec![0u8; signature.len()];

    crate::pkcs1v15::verify_noalloc_generic(key, &SHA1_PREFIX, prehash, &sig, &mut em_storage)
}

#[derive(Clone, Debug)]
pub struct ModMathForm<const N: usize> {
    integer: ModMathFixedUint<N>,
    params: ModMathParams<N>,
}

impl<const N: usize> IntoMontyForm<ModMathParams<N>> for ModMathForm<N> {
    fn from_reduced(integer: ModMathFixedUint<N>, params: &ModMathParams<N>) -> Self {
        Self {
            integer,
            params: params.clone(),
        }
    }
}

impl<const N: usize> Pow<ModMathParams<N>> for ModMathForm<N> {
    fn pow(&self, exp: &ModMathFixedUint<N>) -> Self {
        Self {
            integer: basic_mod_exp(self.integer, *exp, self.params.modulus),
            params: self.params.clone(),
        }
    }

    fn retrieve(&self) -> ModMathFixedUint<N> {
        self.integer
    }
}

impl<const N: usize> PowBoundedExp<ModMathParams<N>> for ModMathForm<N> {
    fn pow_bounded_exp(&self, exp: &ModMathFixedUint<N>, _exp_bits: u32) -> Self {
        self.pow(exp)
    }

    fn retrieve(&self) -> ModMathFixedUint<N> {
        self.integer
    }
}

impl<const N: usize> MParam for ModMathParams<N> {
    type Modulus = ModMathFixedUint<N>;
    type Form = ModMathForm<N>;

    fn modulus(&self) -> &Odd<Self::Modulus> {
        // Safety: `new` rejects zero and even values, matching `Odd<T>` invariants.
        unsafe { &*(&self.modulus as *const _ as *const Odd<Self::Modulus>) }
    }

    fn bits_precision(&self) -> u32 {
        self.modulus.bits_precision()
    }
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct ModMathForm32<const N: usize> {
    integer: ModMathFixedUint32<N>,
    params: ModMathParams32<N>,
}

#[cfg(feature = "alloc")]
impl<const N: usize> IntoMontyForm<ModMathParams32<N>> for ModMathForm32<N> {
    fn from_reduced(integer: ModMathFixedUint32<N>, params: &ModMathParams32<N>) -> Self {
        Self {
            integer,
            params: params.clone(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> Pow<ModMathParams32<N>> for ModMathForm32<N> {
    fn pow(&self, exp: &ModMathFixedUint32<N>) -> Self {
        Self {
            integer: basic_mod_exp(self.integer, *exp, self.params.modulus),
            params: self.params.clone(),
        }
    }

    fn retrieve(&self) -> ModMathFixedUint32<N> {
        self.integer
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> PowBoundedExp<ModMathParams32<N>> for ModMathForm32<N> {
    fn pow_bounded_exp(&self, exp: &ModMathFixedUint32<N>, _exp_bits: u32) -> Self {
        self.pow(exp)
    }

    fn retrieve(&self) -> ModMathFixedUint32<N> {
        self.integer
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> MParam for ModMathParams32<N> {
    type Modulus = ModMathFixedUint32<N>;
    type Form = ModMathForm32<N>;

    fn modulus(&self) -> &Odd<Self::Modulus> {
        unsafe { &*(&self.modulus as *const _ as *const Odd<Self::Modulus>) }
    }

    fn bits_precision(&self) -> u32 {
        self.modulus.bits_precision()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        public_key_from_be_bytes, public_key_from_be_bytes_u32, verify_pkcs1v15_sha1_prehash,
        verify_pkcs1v15_sha1_prehash_u32,
    };

    #[test]
    fn verify_pkcs1v15_signature_with_modmath_fixed_uint() {
        let digest: [u8; 20] = [
            0x43, 0x0c, 0xe3, 0x4d, 0x02, 0x07, 0x24, 0xed, 0x75, 0xa1,
            0x96, 0xdf, 0xc2, 0xad, 0x67, 0xc7, 0x77, 0x72, 0xd1, 0x69,
        ];
        let modulus: [u8; 64] = [
            0x96, 0x9D, 0x03, 0xFF, 0xA9, 0x8D, 0x88, 0x8F, 0x3A, 0xA4, 0xF2, 0xFE, 0xD2, 0x32,
            0xE6, 0x1C, 0x4A, 0xCF, 0x06, 0x63, 0xA9, 0x2F, 0x99, 0x03, 0x4C, 0xF7, 0xB7, 0x24,
            0x5A, 0x1A, 0x1E, 0x5E, 0xAF, 0xA5, 0x65, 0xAF, 0xB9, 0x0B, 0xAB, 0x22, 0x85, 0x71,
            0x2F, 0xAA, 0x50, 0x39, 0x39, 0xA0, 0x65, 0xFB, 0x60, 0xDD, 0x08, 0x28, 0xA3, 0x84,
            0xF2, 0x6D, 0x8A, 0xFC, 0x28, 0x6D, 0xF6, 0xCF,
        ];
        let signature: [u8; 64] = [
            0x45, 0x53, 0xF3, 0xAF, 0x16, 0xAF, 0x63, 0x97, 0xB0, 0xD3, 0x2F, 0x8A, 0xEC, 0xD5,
            0x4C, 0xF1, 0xF3, 0xD0, 0x0C, 0x9F, 0x42, 0xDC, 0x68, 0xCB, 0xD7, 0x05, 0xCE, 0xA5,
            0xA9, 0x70, 0x95, 0x3E, 0xC0, 0xBC, 0x4A, 0x18, 0xED, 0x91, 0xA3, 0x5D, 0x66, 0xEC,
            0xDA, 0x4A, 0x83, 0x32, 0xCF, 0xC3, 0xA3, 0xAB, 0x21, 0xAD, 0x59, 0xB2, 0x2E, 0x87,
            0xC2, 0x73, 0xFF, 0x08, 0x88, 0xDD, 0x4D, 0xE0,
        ];

        let key = public_key_from_be_bytes(&modulus, 3).unwrap();
        verify_pkcs1v15_sha1_prehash(&key, &digest, &signature).unwrap();
    }

    #[test]
    fn verify_pkcs1v15_signature_with_modmath_fixed_uint32() {
        let digest: [u8; 20] = [
            0x43, 0x0c, 0xe3, 0x4d, 0x02, 0x07, 0x24, 0xed, 0x75, 0xa1,
            0x96, 0xdf, 0xc2, 0xad, 0x67, 0xc7, 0x77, 0x72, 0xd1, 0x69,
        ];
        let modulus: [u8; 64] = [
            0x96, 0x9D, 0x03, 0xFF, 0xA9, 0x8D, 0x88, 0x8F, 0x3A, 0xA4, 0xF2, 0xFE, 0xD2, 0x32,
            0xE6, 0x1C, 0x4A, 0xCF, 0x06, 0x63, 0xA9, 0x2F, 0x99, 0x03, 0x4C, 0xF7, 0xB7, 0x24,
            0x5A, 0x1A, 0x1E, 0x5E, 0xAF, 0xA5, 0x65, 0xAF, 0xB9, 0x0B, 0xAB, 0x22, 0x85, 0x71,
            0x2F, 0xAA, 0x50, 0x39, 0x39, 0xA0, 0x65, 0xFB, 0x60, 0xDD, 0x08, 0x28, 0xA3, 0x84,
            0xF2, 0x6D, 0x8A, 0xFC, 0x28, 0x6D, 0xF6, 0xCF,
        ];
        let signature: [u8; 64] = [
            0x45, 0x53, 0xF3, 0xAF, 0x16, 0xAF, 0x63, 0x97, 0xB0, 0xD3, 0x2F, 0x8A, 0xEC, 0xD5,
            0x4C, 0xF1, 0xF3, 0xD0, 0x0C, 0x9F, 0x42, 0xDC, 0x68, 0xCB, 0xD7, 0x05, 0xCE, 0xA5,
            0xA9, 0x70, 0x95, 0x3E, 0xC0, 0xBC, 0x4A, 0x18, 0xED, 0x91, 0xA3, 0x5D, 0x66, 0xEC,
            0xDA, 0x4A, 0x83, 0x32, 0xCF, 0xC3, 0xA3, 0xAB, 0x21, 0xAD, 0x59, 0xB2, 0x2E, 0x87,
            0xC2, 0x73, 0xFF, 0x08, 0x88, 0xDD, 0x4D, 0xE0,
        ];

        let key = public_key_from_be_bytes_u32::<16>(&modulus, 3).unwrap();
        verify_pkcs1v15_sha1_prehash_u32(&key, &digest, &signature).unwrap();
    }
}
