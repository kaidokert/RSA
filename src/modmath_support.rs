//! Generic `modmath` backend adapters for fixed-width RSA public-key paths.
//!

// TODO: document the public surface once the trait shape settles.
#![allow(missing_docs)]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::ops::{Shr, ShrAssign};

use fixed_bigint::{Ct, Nct, Personality};
use modmath::{CiosMontMul, CiosMontMulCt, Field as ModmathField, Parity, WideMul};
use num_traits::ops::overflowing::OverflowingAdd;
use num_traits::ops::wrapping::{WrappingAdd, WrappingMul, WrappingSub};
use num_traits::{One, Zero};
use zeroize::Zeroize;

use crate::{
    algorithms::rsa::rsa_encrypt,
    errors::{Error, Result},
    key::GenericRsaPublicKey,
    traits::modular::{
        FixedWidthUnsignedInt, IntegerResize, IntoMontyForm, ModulusParams, NonZero, Odd, Pow,
        PowBoundedExp, TryFromBeBytes, UnsignedModularInt,
    },
};

pub trait ModMathInt:
    FixedWidthUnsignedInt
    + From<u8>
    + PartialEq
    + PartialOrd
    + One
    + Zero
    + Parity
    + OverflowingAdd
    + WideMul
    + CiosMontMul
    + WrappingAdd
    + WrappingMul
    + WrappingSub
    + Shr<usize, Output = Self>
    + ShrAssign<usize>
{
}

impl<T> ModMathInt for T where
    T: FixedWidthUnsignedInt
        + From<u8>
        + PartialEq
        + PartialOrd
        + One
        + Zero
        + Parity
        + OverflowingAdd
        + WideMul
        + CiosMontMul
        + WrappingAdd
        + WrappingMul
        + WrappingSub
        + Shr<usize, Output = Self>
        + ShrAssign<usize>
{
}

pub trait ModMathIntCt:
    FixedWidthUnsignedInt
    + From<u8>
    + PartialEq
    + PartialOrd
    + One
    + Zero
    + Parity
    + OverflowingAdd
    + WideMul
    + CiosMontMulCt
    + WrappingAdd
    + WrappingMul
    + WrappingSub
    + Shr<usize, Output = Self>
    + ShrAssign<usize>
    + subtle::ConditionallySelectable
    + subtle::ConstantTimeLess
    + core::ops::BitAnd<Output = Self>
{
}

impl<T> ModMathIntCt for T where
    T: FixedWidthUnsignedInt
        + From<u8>
        + PartialEq
        + PartialOrd
        + One
        + Zero
        + Parity
        + OverflowingAdd
        + WideMul
        + CiosMontMulCt
        + WrappingAdd
        + WrappingMul
        + WrappingSub
        + Shr<usize, Output = Self>
        + ShrAssign<usize>
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + core::ops::BitAnd<Output = Self>
{
}

#[cfg(feature = "alloc")]
fn wrap_value<T>(value: T) -> ModMathValue<T> {
    ModMathValue(value)
}

#[cfg(not(feature = "alloc"))]
fn wrap_value<T>(value: T) -> ModMathValue<T> {
    value
}

#[cfg(feature = "alloc")]
fn unwrap_value<T: Copy>(value: &ModMathValue<T>) -> T {
    value.0
}

#[cfg(feature = "alloc")]
fn unwrap_value_ref<T>(value: &ModMathValue<T>) -> &T {
    &value.0
}

#[cfg(not(feature = "alloc"))]
fn unwrap_value_ref<T>(value: &ModMathValue<T>) -> &T {
    value
}

#[cfg(not(feature = "alloc"))]
fn unwrap_value<T: Copy>(value: &ModMathValue<T>) -> T {
    *value
}

#[cfg(feature = "alloc")]
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ModMathValue<T>(pub T);

#[cfg(feature = "alloc")]
impl<T> ModMathValue<T> {
    pub fn from_inner(inner: T) -> Self {
        Self(inner)
    }

    pub fn inner(&self) -> &T {
        &self.0
    }
}

#[cfg(feature = "alloc")]
impl<T> Zeroize for ModMathValue<T>
where
    T: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "alloc")]
impl<T> From<u8> for ModMathValue<T>
where
    T: From<u8>,
{
    fn from(value: u8) -> Self {
        Self(<T as From<u8>>::from(value))
    }
}

#[cfg(feature = "alloc")]
impl<T> IntegerResize for ModMathValue<T>
where
    T: FixedWidthUnsignedInt + PartialOrd,
{
    type Output = Self;

    fn resize_unchecked(self, _at_least_bits_precision: u32) -> Self::Output {
        self
    }

    fn try_resize(self, at_least_bits_precision: u32) -> Option<Self::Output> {
        // Mirrors `crypto_bigint::Resize::try_resize`: returns `Some` iff
        // the actual value fits in `at_least_bits_precision` bits. Our
        // type is fixed-width and `resize_unchecked` is a no-op, but the
        // check still needs to reject values that wouldn't survive a
        // narrower precision.
        let value_bits = self.bits_precision() - self.leading_zeros();
        if value_bits <= at_least_bits_precision {
            Some(self)
        } else {
            None
        }
    }
}

#[cfg(feature = "alloc")]
impl<T> UnsignedModularInt for ModMathValue<T>
where
    T: FixedWidthUnsignedInt + PartialOrd,
{
    type Bytes = <T as FixedWidthUnsignedInt>::Bytes;

    fn leading_zeros(&self) -> u32 {
        FixedWidthUnsignedInt::leading_zeros(&self.0)
    }

    fn to_be_bytes(&self) -> Self::Bytes {
        FixedWidthUnsignedInt::to_be_bytes(&self.0)
    }

    #[cfg(feature = "alloc")]
    fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        let bytes = self.to_be_bytes();
        let bytes = bytes.as_ref();
        let first_non_zero = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len().saturating_sub(1));
        bytes[first_non_zero..].to_vec().into_boxed_slice()
    }

    fn as_nz_ref(&self) -> NonZero<Self> {
        NonZero::new(*self).expect("value is non-zero")
    }

    fn bits(&self) -> u32 {
        self.bits_precision() - self.leading_zeros()
    }

    fn bits_precision(&self) -> u32 {
        FixedWidthUnsignedInt::bits_precision(&self.0)
    }
}

#[cfg(feature = "alloc")]
impl<T> TryFromBeBytes for ModMathValue<T>
where
    T: FixedWidthUnsignedInt,
{
    fn try_from_be_bytes_vartime(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            <T as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(bytes)?,
        ))
    }
}

#[cfg(not(feature = "alloc"))]
pub type ModMathValue<T> = T;

#[derive(Clone, Debug)]
pub struct ModMathParams<T, P: Personality = Nct> {
    // Owns the modulus + precomputed Montgomery constants. `Clone` is a
    // trivial 4×T memcpy per modmath::Field's documented guarantee — does
    // NOT re-run `compute_r_mod_n` / `compute_r2_mod_n`.
    field: ModmathField<T, P>,
    // Parallel copy of the modulus, wrapped in `Odd` for the
    // `ModulusParams::modulus() -> &Odd<...>` trait interface. Duplicates
    // `field.modulus()` (one extra T per params, one extra T-sized memcpy
    // per clone) — cheap, and lets `modulus()` return a real reference
    // instead of transmuting through `repr(transparent)`.
    modulus_odd: Odd<ModMathValue<T>>,
}

impl<T: ModMathInt> ModMathParams<T, Nct> {
    pub fn new(modulus: T) -> Result<Self> {
        let field = ModmathField::<T, Nct>::new(modulus).ok_or(Error::InvalidModulus)?;
        let modulus_odd = Odd::new(wrap_value(modulus)).ok_or(Error::InvalidModulus)?;
        Ok(Self { field, modulus_odd })
    }
}

impl<T: ModMathIntCt> ModMathParams<T, Ct> {
    /// Create CT (encrypt) Montgomery parameters for an odd, non-zero
    /// modulus.
    pub fn new(modulus: T) -> Result<Self> {
        let field = ModmathField::<T, Ct>::new(modulus).ok_or(Error::InvalidModulus)?;
        let modulus_odd = Odd::new(wrap_value(modulus)).ok_or(Error::InvalidModulus)?;
        Ok(Self { field, modulus_odd })
    }
}

impl<T, P: Personality> ModMathParams<T, P> {
    pub(crate) fn field(&self) -> &ModmathField<T, P> {
        &self.field
    }
}

/// Construct an **NCT** public key from big-endian modulus bytes and a public
/// exponent. Use this for signature verification.
pub fn public_key_from_be_bytes<T>(
    modulus: &[u8],
    exponent: u32,
) -> Result<GenericRsaPublicKey<ModMathValue<T>, ModMathParams<T, Nct>>>
where
    T: ModMathInt,
{
    let n = wrap_value(<T as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(
        modulus,
    )?);
    let exponent = exponent.to_be_bytes();
    let e = wrap_value(<T as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(
        &exponent,
    )?);
    GenericRsaPublicKey::from_components(n, e, ModMathParams::<T, Nct>::new(unwrap_value(&n))?)
}

/// Apply the raw RSA public operation to a fixed-width block using the **NCT**
/// (vartime) Montgomery path. Intended for signature verification.
pub fn rsa_public_op<T>(
    key: &GenericRsaPublicKey<ModMathValue<T>, ModMathParams<T, Nct>>,
    input: &[u8],
) -> Result<<ModMathValue<T> as UnsignedModularInt>::Bytes>
where
    T: ModMathInt,
{
    let input = wrap_value(<T as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(
        input,
    )?);
    Ok(rsa_encrypt(key, &input)?.to_be_bytes())
}

/// Construct a **CT** public key. Use this when the resulting key will feed
/// PKCS#1 v1.5 / OAEP encryption (or any other path where the plaintext is
/// secret). `T` must be a Ct-typed FixedUInt; the bound is enforced by the
/// `CiosMontMulCt` requirement inside [`ModMathIntCt`].
pub fn public_key_ct_from_be_bytes<T>(
    modulus: &[u8],
    exponent: u32,
) -> Result<GenericRsaPublicKey<ModMathValue<T>, ModMathParams<T, Ct>>>
where
    T: ModMathIntCt,
{
    let n = wrap_value(<T as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(
        modulus,
    )?);
    let exponent = exponent.to_be_bytes();
    let e = wrap_value(<T as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(
        &exponent,
    )?);
    GenericRsaPublicKey::from_components(n, e, ModMathParams::<T, Ct>::new(unwrap_value(&n))?)
}

pub fn rsa_public_op_ct<T>(
    key: &GenericRsaPublicKey<ModMathValue<T>, ModMathParams<T, Ct>>,
    input: &[u8],
) -> Result<<ModMathValue<T> as UnsignedModularInt>::Bytes>
where
    T: ModMathIntCt,
{
    let input = wrap_value(<T as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(
        input,
    )?);
    Ok(rsa_encrypt(key, &input)?.to_be_bytes())
}

// `T: Zeroize` (not just `Clone`) is locked in to satisfy `Drop` coherence
// below — loosening it silently disables the auto-wipe.
#[derive(Clone, Debug)]
pub struct ModMathForm<T, P: Personality = Nct>
where
    T: Clone + Zeroize,
{
    integer_mont: ModMathValue<T>,
    params: ModMathParams<T, P>,
}

// `integer_mont` is secret-derived Montgomery state; `params` is public.
impl<T, P: Personality> Zeroize for ModMathForm<T, P>
where
    T: Clone + Zeroize,
{
    fn zeroize(&mut self) {
        self.integer_mont.zeroize();
    }
}

impl<T, P: Personality> Drop for ModMathForm<T, P>
where
    T: Clone + Zeroize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T, P: Personality> zeroize::ZeroizeOnDrop for ModMathForm<T, P> where T: Clone + Zeroize {}

impl<T: ModMathInt> IntoMontyForm<ModMathParams<T, Nct>> for ModMathForm<T, Nct> {
    fn from_reduced(integer: ModMathValue<T>, params: &ModMathParams<T, Nct>) -> Self {
        let field = params.field();
        let r = field.reduce(unwrap_value_ref(&integer));
        Self {
            integer_mont: wrap_value(*r.mont_value()),
            params: params.clone(),
        }
    }

    /// `Field::reduce` is `raw * R² mod modulus` via CIOS — well-defined for
    /// any `raw < R = 2^W`. Same body as `from_reduced` because the
    /// underlying primitive already handles unreduced input.
    fn from_value(integer: ModMathValue<T>, params: &ModMathParams<T, Nct>) -> Self {
        Self::from_reduced(integer, params)
    }
}

impl<T: ModMathInt> ModMathForm<T, Nct> {
    fn pow_loop(&self, exp_raw: T) -> T {
        let field = self.params.field();
        let base = field.residue_from_mont(unwrap_value(&self.integer_mont));
        *field.exp(&base, &exp_raw).mont_value()
    }

    fn to_reduced(&self) -> T {
        let field = self.params.field();
        let r = field.residue_from_mont(unwrap_value(&self.integer_mont));
        field.into_raw(&r)
    }
}

impl<T: ModMathInt> Pow<ModMathParams<T, Nct>> for ModMathForm<T, Nct> {
    fn pow(&self, exp: &ModMathValue<T>) -> Self {
        let result_mont = self.pow_loop(unwrap_value(exp));
        Self {
            integer_mont: wrap_value(result_mont),
            params: self.params.clone(),
        }
    }
}

impl<T: ModMathInt> PowBoundedExp<ModMathParams<T, Nct>> for ModMathForm<T, Nct> {
    fn pow_bounded_exp(&self, exp: &ModMathValue<T>, _exp_bits: u32) -> Self {
        // The LSB-first loop exits naturally when the exponent reaches zero,
        // so the `_exp_bits` hint is unused here.
        let result_mont = self.pow_loop(unwrap_value(exp));
        Self {
            integer_mont: wrap_value(result_mont),
            params: self.params.clone(),
        }
    }

    fn retrieve(&self) -> ModMathValue<T> {
        wrap_value(self.to_reduced())
    }
}

impl<T: ModMathInt> ModulusParams for ModMathParams<T, Nct> {
    type Modulus = ModMathValue<T>;
    type MontgomeryForm = ModMathForm<T, Nct>;

    fn modulus(&self) -> &Odd<Self::Modulus> {
        &self.modulus_odd
    }

    fn bits_precision(&self) -> u32 {
        FixedWidthUnsignedInt::bits_precision(self.field.modulus())
    }
}

impl<T: ModMathIntCt> IntoMontyForm<ModMathParams<T, Ct>> for ModMathForm<T, Ct> {
    fn from_reduced(integer: ModMathValue<T>, params: &ModMathParams<T, Ct>) -> Self {
        let field = params.field();
        let r = field.reduce(unwrap_value_ref(&integer));
        Self {
            integer_mont: wrap_value(*r.mont_value()),
            params: params.clone(),
        }
    }

    /// Same as the Nct variant: `FieldCt::reduce` uses `wide_montgomery_mul_ct`
    /// with `R² mod modulus`, which handles arbitrary `raw < R = 2^W`.
    fn from_value(integer: ModMathValue<T>, params: &ModMathParams<T, Ct>) -> Self {
        Self::from_reduced(integer, params)
    }
}

impl<T: ModMathIntCt> ModMathForm<T, Ct> {
    // Secret-exponent ladder. Used by `Pow::pow`, which is the path RSA
    // signing and unblinded decryption reduce to — the exponent is `d`,
    // never disclosed in timing. Routes to modmath's `Field<T, Ct>::exp`,
    // a fixed-iteration Montgomery ladder with branchless per-bit select.
    fn pow_loop_ct(&self, exp_raw: T) -> T {
        let field = self.params.field();
        let base = field.residue_from_mont(unwrap_value(&self.integer_mont));
        *field.exp(&base, &exp_raw).mont_value()
    }

    // Public-exponent ladder. Used by `PowBoundedExp::pow_bounded_exp`,
    // which acknowledges variable-time-in-exponent semantics — the
    // exponent is `e` (RSA public verify/encrypt), already disclosed.
    // Routes to modmath's `Field<T, Ct>::exp_public_exp`.
    fn pow_loop_public_exp(&self, exp_raw: T) -> T {
        let field = self.params.field();
        let base = field.residue_from_mont(unwrap_value(&self.integer_mont));
        *field.exp_public_exp(&base, &exp_raw).mont_value()
    }

    fn to_reduced(&self) -> T {
        let field = self.params.field();
        let r = field.residue_from_mont(unwrap_value(&self.integer_mont));
        field.into_raw(&r)
    }
}

impl<T: ModMathIntCt> Pow<ModMathParams<T, Ct>> for ModMathForm<T, Ct> {
    fn pow(&self, exp: &ModMathValue<T>) -> Self {
        let result_mont = self.pow_loop_ct(unwrap_value(exp));
        Self {
            integer_mont: wrap_value(result_mont),
            params: self.params.clone(),
        }
    }
}

impl<T: ModMathIntCt> PowBoundedExp<ModMathParams<T, Ct>> for ModMathForm<T, Ct> {
    fn pow_bounded_exp(&self, exp: &ModMathValue<T>, _exp_bits: u32) -> Self {
        let result_mont = self.pow_loop_public_exp(unwrap_value(exp));
        Self {
            integer_mont: wrap_value(result_mont),
            params: self.params.clone(),
        }
    }

    fn retrieve(&self) -> ModMathValue<T> {
        wrap_value(self.to_reduced())
    }
}

impl<T: ModMathIntCt> ModulusParams for ModMathParams<T, Ct> {
    type Modulus = ModMathValue<T>;
    type MontgomeryForm = ModMathForm<T, Ct>;

    fn modulus(&self) -> &Odd<Self::Modulus> {
        &self.modulus_odd
    }

    fn bits_precision(&self) -> u32 {
        FixedWidthUnsignedInt::bits_precision(self.field.modulus())
    }
}

#[cfg(test)]
#[cfg(all(feature = "alloc", feature = "private-key"))]
mod tests {
    use fixed_bigint::{Ct, FixedUInt};
    use rand::rngs::ChaCha8Rng;
    use rand_core::SeedableRng;
    use sha1::Sha1;
    use signature::hazmat::PrehashVerifier;

    use super::{
        public_key_ct_from_be_bytes, public_key_from_be_bytes, ModMathForm, ModMathParams,
        ModMathValue,
    };
    use crate::key::GenericRsaPublicKey;
    use crate::pkcs1v15::{GenericEncryptingKey, GenericSignature, GenericVerifyingKey};
    use crate::{traits::RandomizedEncryptor, BoxedUint, Pkcs1v15Encrypt, RsaPublicKey};

    type SmallU = FixedUInt<u8, 64>;
    type SmallUCt = FixedUInt<u8, 64, Ct>;

    #[test]
    fn brand_round_trip() {
        let params = ModMathParams::<SmallU>::new(SmallU::from(13u8)).unwrap();
        let f = params.field();
        let r = f.reduce(&SmallU::from(7u8));
        assert_eq!(f.into_raw(&r), SmallU::from(7u8));
    }

    #[test]
    fn brand_mul_exp() {
        let params = ModMathParams::<SmallU>::new(SmallU::from(13u8)).unwrap();
        let f = params.field();
        // 7 * 11 = 77 ≡ 12 (mod 13)
        let a = f.reduce(&SmallU::from(7u8));
        let b = f.reduce(&SmallU::from(11u8));
        assert_eq!(f.into_raw(&f.mul(&a, &b)), SmallU::from(12u8));
        // 2^10 = 1024 ≡ 10 (mod 13)
        let base = f.reduce(&SmallU::from(2u8));
        assert_eq!(
            f.into_raw(&f.exp(&base, &SmallU::from(10u8))),
            SmallU::from(10u8)
        );
    }

    #[test]
    fn brand_ct_matches_nct() {
        let p_nct = ModMathParams::<SmallU>::new(SmallU::from(13u8)).unwrap();
        let p_ct = ModMathParams::<SmallUCt, Ct>::new(SmallUCt::from(13u8)).unwrap();
        let f_nct = p_nct.field();
        let f_ct = p_ct.field();
        let nct = f_nct.into_raw(&f_nct.mul(
            &f_nct.reduce(&SmallU::from(7u8)),
            &f_nct.reduce(&SmallU::from(11u8)),
        ));
        let ct = f_ct.into_raw(&f_ct.mul(
            &f_ct.reduce(&SmallUCt::from(7u8)),
            &f_ct.reduce(&SmallUCt::from(11u8)),
        ));
        // Distinct types — compare via underlying byte representation.
        let mut nct_bytes = [0u8; 64];
        let mut ct_bytes = [0u8; 64];
        let _ = nct.to_be_bytes(&mut nct_bytes);
        let _ = ct.to_be_bytes(&mut ct_bytes);
        assert_eq!(nct_bytes, ct_bytes);
    }

    #[test]
    fn mod_math_form_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ModMathForm<SmallU>>();
        assert_zeroize_on_drop::<ModMathForm<SmallUCt, Ct>>();
    }

    #[test]
    fn verify_pkcs1v15_signature_with_modmath_fixed_uint() {
        type U512 = FixedUInt<u8, 64>;

        let digest: [u8; 20] = [
            0x43, 0x0c, 0xe3, 0x4d, 0x02, 0x07, 0x24, 0xed, 0x75, 0xa1, 0x96, 0xdf, 0xc2, 0xad,
            0x67, 0xc7, 0x77, 0x72, 0xd1, 0x69,
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

        let key = public_key_from_be_bytes::<U512>(&modulus, 3).unwrap();
        let verifying_key = GenericVerifyingKey::<Sha1, _, _>::new(key);
        let signature =
            GenericSignature::from(ModMathValue::from_inner(U512::from_be_bytes(&signature)));
        verifying_key.verify_prehash(&digest, &signature).unwrap();
    }

    #[test]
    fn verify_pkcs1v15_signature_with_modmath_fixed_uint32() {
        type U512 = FixedUInt<u32, 16>;

        let digest: [u8; 20] = [
            0x43, 0x0c, 0xe3, 0x4d, 0x02, 0x07, 0x24, 0xed, 0x75, 0xa1, 0x96, 0xdf, 0xc2, 0xad,
            0x67, 0xc7, 0x77, 0x72, 0xd1, 0x69,
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

        let n = U512::from_be_bytes(&modulus);
        let e = U512::from(3u8);
        // Turbofish the personality: `ModMathParams::new` is ambiguous
        // between the Nct and Ct impl blocks (the `P = Nct` default doesn't
        // fire in inference contexts). Pin Nct explicitly.
        let key = GenericRsaPublicKey::from_components(
            ModMathValue::from_inner(n),
            ModMathValue::from_inner(e),
            ModMathParams::<U512, fixed_bigint::Nct>::new(n).unwrap(),
        )
        .unwrap();
        let verifying_key = GenericVerifyingKey::<Sha1, _, _>::new(key);
        let signature =
            GenericSignature::from(ModMathValue::from_inner(U512::from_be_bytes(&signature)));
        verifying_key.verify_prehash(&digest, &signature).unwrap();
    }

    #[test]
    fn encrypt_pkcs1v15_with_modmath_fixed_uint_matches_boxeduint() {
        // Encrypt path takes a secret plaintext, so type the modulus as
        // Ct-personality — `CiosMontMulCt` only resolves for Ct-typed
        // FixedUInts under the personality typestate.
        type U512 = FixedUInt<u8, 64, Ct>;

        let modulus: [u8; 64] = [
            0x96, 0x9D, 0x03, 0xFF, 0xA9, 0x8D, 0x88, 0x8F, 0x3A, 0xA4, 0xF2, 0xFE, 0xD2, 0x32,
            0xE6, 0x1C, 0x4A, 0xCF, 0x06, 0x63, 0xA9, 0x2F, 0x99, 0x03, 0x4C, 0xF7, 0xB7, 0x24,
            0x5A, 0x1A, 0x1E, 0x5E, 0xAF, 0xA5, 0x65, 0xAF, 0xB9, 0x0B, 0xAB, 0x22, 0x85, 0x71,
            0x2F, 0xAA, 0x50, 0x39, 0x39, 0xA0, 0x65, 0xFB, 0x60, 0xDD, 0x08, 0x28, 0xA3, 0x84,
            0xF2, 0x6D, 0x8A, 0xFC, 0x28, 0x6D, 0xF6, 0xCF,
        ];
        let msg = b"hello world!";

        let modmath_key = public_key_ct_from_be_bytes::<U512>(&modulus, 3).unwrap();
        let boxed_key = RsaPublicKey::new(
            BoxedUint::from_be_slice(&modulus, 512).unwrap(),
            3u64.into(),
        )
        .unwrap();

        let mut modmath_rng = ChaCha8Rng::from_seed([42; 32]);
        let mut boxed_rng = ChaCha8Rng::from_seed([42; 32]);
        let mut storage = [0u8; 64];

        let modmath_ciphertext = GenericEncryptingKey::new(modmath_key)
            .encrypt_with_rng_into(&mut modmath_rng, msg, &mut storage)
            .unwrap();
        let boxed_ciphertext = boxed_key
            .encrypt(&mut boxed_rng, Pkcs1v15Encrypt, msg)
            .unwrap();

        assert_eq!(modmath_ciphertext, boxed_ciphertext.as_slice());
    }
}

// Tests for the `rsa_private_op` primitive on the heapless / Ct path.
// Gated independently of the alloc+private-key block above so the
// `wip-private-key` feature (which doesn't imply alloc) can compile
// and run them in no_alloc mode.
#[cfg(test)]
#[cfg(any(feature = "private-key", feature = "wip-private-key"))]
mod private_op_tests {
    use super::*;
    use fixed_bigint::{Ct, FixedUInt};

    type SmallUCt = FixedUInt<u8, 64, Ct>;

    // n = 35 = 5 · 7, φ(n) = 24. e = 5, d = 29 (since 5·29 = 145 ≡ 1 mod 24).
    // m = 2 → c = 2^5 mod 35 = 32 → m_recovered = 32^29 mod 35 = 2.
    fn toy_params() -> ModMathParams<SmallUCt, Ct> {
        ModMathParams::<SmallUCt, Ct>::new(SmallUCt::from(35u8)).unwrap()
    }

    #[test]
    fn rsa_private_op_round_trip_heapless_ct() {
        let n_params = toy_params();
        let c = wrap_value(SmallUCt::from(32u8));
        let d = wrap_value(SmallUCt::from(29u8));
        let expected = wrap_value(SmallUCt::from(2u8));
        let recovered = crate::algorithms::rsa::rsa_private_op(&c, &d, &n_params);
        assert_eq!(recovered, expected);
    }

    #[test]
    fn rsa_private_op_and_check_round_trip_heapless_ct() {
        let n_params = toy_params();
        let c = wrap_value(SmallUCt::from(32u8));
        let d = wrap_value(SmallUCt::from(29u8));
        let e = wrap_value(SmallUCt::from(5u8));
        let expected = wrap_value(SmallUCt::from(2u8));
        let recovered =
            crate::algorithms::rsa::rsa_private_op_and_check(&c, &d, &e, &n_params).unwrap();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn rsa_private_op_and_check_rejects_wrong_exponent() {
        // Same modulus + e, but a wrong `d` (11 instead of 29). The recovered
        // `m` won't re-encrypt back to `c`, so the integrity check should fail.
        let n_params = toy_params();
        let c = wrap_value(SmallUCt::from(32u8));
        let bad_d = wrap_value(SmallUCt::from(11u8));
        let e = wrap_value(SmallUCt::from(5u8));
        let result = crate::algorithms::rsa::rsa_private_op_and_check(&c, &bad_d, &e, &n_params);
        assert!(result.is_err());
    }

    // 2048-bit RSA keypair fixture — same `(n, e=65537, d)` used in
    // `algorithms::rsa::tests::recover_primes_works`. Pulled in here so the
    // heapless wip-private-key test path can roundtrip-sign without
    // requiring `alloc`. `e` is rendered as 3-byte BE (`0x010001`) and
    // resized into `U2048` at test time.
    const N_2048: [u8; 256] = hex_literal::hex!(
        "d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222
         b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e
         74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb
         28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7
         ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078c
         c780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2
         e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf67
         76fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b"
    );
    const D_2048: [u8; 256] = hex_literal::hex!(
        "c4e70c689162c94c660828191b52b4d8392115df486a9adbe831e458d7395832
         0dc1b755456e93701e9702d76fb0b92f90e01d1fe248153281fe79aa9763a92f
         ae69d8d7ecd144de29fa135bd14f9573e349e45031e3b76982f583003826c552
         e89a397c1a06bd2163488630d92e8c2bb643d7abef700da95d685c941489a46f
         54b5316f62b5d2c3a7f1bbd134cb37353a44683fdc9d95d36458de22f6c44057
         fe74a0a436c4308f73f4da42f35c47ac16a7138d483afc91e41dc3a1127382e0
         c0f5119b0221b4fc639d6b9c38177a6de9b526ebd88c38d7982c07f98a0efd87
         7d508aae275b946915c02e2e1106d175d74ec6777f5e80d12c053d9c7be1e341"
    );

    #[test]
    fn pkcs1v15_sign_into_round_trip_2048_sha1() {
        use crate::algorithms::pkcs1v15::{
            pkcs1v15_generate_prefix_into, pkcs1v15_sign_pad_into, sign_into,
        };
        use crate::traits::PublicKeyParts;
        use sha1::Sha1;

        type U2048 = FixedUInt<u8, 256, Ct>;
        const K: usize = 256;

        let key = public_key_ct_from_be_bytes::<U2048>(&N_2048, 65537).unwrap();
        let d_int = <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&D_2048).unwrap();
        let d = wrap_value(d_int);
        let e_int =
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&[0x01, 0x00, 0x01])
                .unwrap();
        let e = wrap_value(e_int);

        let digest = [0xAAu8; 20];
        let mut prefix_storage = [0u8; 32];
        let prefix = pkcs1v15_generate_prefix_into::<Sha1>(&mut prefix_storage).unwrap();

        let mut em_storage = [0u8; K];
        let mut sig_storage = [0u8; K];
        let sig = sign_into(
            key.n_params(),
            &d,
            &e,
            prefix,
            &digest,
            K,
            &mut em_storage,
            &mut sig_storage,
        )
        .unwrap();
        assert_eq!(sig.len(), K);

        // Roundtrip via public op: `sig^e mod n` must recover the padded EM
        // that `pkcs1v15_sign_pad_into` produces for the same (prefix, digest).
        let recovered = public_key_op_ct(&key, sig).unwrap();
        let mut expected_em_storage = [0u8; K];
        let expected_em =
            pkcs1v15_sign_pad_into(prefix, &digest, K, &mut expected_em_storage).unwrap();
        assert_eq!(recovered.as_ref(), expected_em);
    }

    // Local alias for `rsa_public_op_ct` — keeps the test's call-site short.
    fn public_key_op_ct<T>(
        key: &crate::key::GenericRsaPublicKey<ModMathValue<T>, ModMathParams<T, Ct>>,
        input: &[u8],
    ) -> Result<<ModMathValue<T> as UnsignedModularInt>::Bytes>
    where
        T: ModMathIntCt,
    {
        crate::modmath_support::rsa_public_op_ct(key, input)
    }
}
