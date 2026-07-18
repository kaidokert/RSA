//! Generic `modmath` backend adapters for fixed-width RSA public-key paths.
//!

// TODO: document the public surface once the trait shape settles.
#![allow(missing_docs)]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::ops::{Shr, ShrAssign};

use const_num_traits::ops::overflowing::OverflowingAdd;
use const_num_traits::ops::wrapping::{WrappingAdd, WrappingMul, WrappingSub};
use const_num_traits::FromByteSlice;
use const_num_traits::WithPrecision;
use const_num_traits::{Ct, HasPersonality, Nct, Personality};
use const_num_traits::{One, Zero};
use modmath::{CiosMontMul, CiosMontMulCt, Field as ModmathField, Parity, WideMul};
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
    + OverflowingAdd<Output = Self>
    + WideMul
    + CiosMontMul
    + WrappingAdd<Output = Self>
    + WrappingMul<Output = Self>
    + WrappingSub<Output = Self>
    + Shr<usize, Output = Self>
    + ShrAssign<usize>
    + HasPersonality
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
        + OverflowingAdd<Output = Self>
        + WideMul
        + CiosMontMul
        + WrappingAdd<Output = Self>
        + WrappingMul<Output = Self>
        + WrappingSub<Output = Self>
        + Shr<usize, Output = Self>
        + ShrAssign<usize>
        + HasPersonality
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
    + OverflowingAdd<Output = Self>
    + WideMul
    + CiosMontMulCt
    + WrappingAdd<Output = Self>
    + WrappingMul<Output = Self>
    + WrappingSub<Output = Self>
    + Shr<usize, Output = Self>
    + ShrAssign<usize>
    + subtle::ConditionallySelectable
    + subtle::ConstantTimeLess
    + core::ops::BitAnd<Output = Self>
    + HasPersonality
    + const_num_traits::CtIsZero
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
        + OverflowingAdd<Output = Self>
        + WideMul
        + CiosMontMulCt
        + WrappingAdd<Output = Self>
        + WrappingMul<Output = Self>
        + WrappingSub<Output = Self>
        + Shr<usize, Output = Self>
        + ShrAssign<usize>
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + core::ops::BitAnd<Output = Self>
        + HasPersonality
        + const_num_traits::CtIsZero
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

/// Cross-config constructor for [`ModMathValue`]. Under `alloc` it is
/// the newtype constructor; under no-alloc `ModMathValue<T>` is a
/// transparent alias for `T`, so it is the identity.
///
/// Prefer this over writing `ModMathValue(x)` directly: the tuple form
/// only compiles on the `alloc` build and breaks the no-alloc one
/// (`expected function / tuple struct, found type alias`). This is the
/// only way to wrap a raw carrier value that compiles under both
/// feature configurations.
#[cfg(feature = "alloc")]
pub fn wrap<T>(value: T) -> ModMathValue<T> {
    ModMathValue(value)
}

/// See [`wrap`] — the no-alloc identity form.
#[cfg(not(feature = "alloc"))]
pub fn wrap<T>(value: T) -> ModMathValue<T> {
    value
}

/// Cross-config unwrap for [`ModMathValue`]: `.0` under `alloc`, the
/// identity under no-alloc. Prefer this over `.0` in code that must
/// compile under both feature configurations. By-value (does not
/// require `T: Copy`).
#[cfg(feature = "alloc")]
pub fn into_inner<T>(value: ModMathValue<T>) -> T {
    value.0
}

/// See [`into_inner`] — the no-alloc identity form.
#[cfg(not(feature = "alloc"))]
pub fn into_inner<T>(value: ModMathValue<T>) -> T {
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

    fn resize_unchecked(self, at_least_bits_precision: u32) -> Self::Output {
        // `T` is our fixed-bigint carrier (it satisfies `FixedWidthUnsignedInt`,
        // hence `WithPrecision`), so establish the operating width on the
        // wrapped value — a real widen on a runtime-length carrier, the
        // identity on a fixed-width one. Matches the no-alloc `T` impl in
        // `traits::modular`; this is not the upstream `BoxedUint` path
        // (that has its own `IntegerResize` via `crypto_bigint::Resize`).
        Self(WithPrecision::widen_to_precision(
            self.0,
            at_least_bits_precision,
        ))
    }

    fn try_resize(self, at_least_bits_precision: u32) -> Option<Self::Output> {
        // Mirrors `crypto_bigint::Resize::try_resize`: `Some` iff the value
        // fits in `at_least_bits_precision` bits, resized to that width.
        let value_bits = self.0.bit_length();
        if value_bits <= at_least_bits_precision {
            Some(Self(WithPrecision::widen_to_precision(
                self.0,
                at_least_bits_precision,
            )))
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
        FixedWidthUnsignedInt::bit_length(&self.0)
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

// Opt the alloc-side newtype into raw `(public_key, d)` private-key
// construction. The heapless-build blanket on
// `FixedWidthUnsignedInt + PartialOrd` doesn't reach `ModMathValue<T>`
// (a newtype, not itself `FixedWidthUnsignedInt`), so impl it here.
#[cfg(feature = "alloc")]
impl<T> crate::traits::keys::RawPrivateKeyConstructible for ModMathValue<T> where
    T: FixedWidthUnsignedInt + PartialOrd
{
}

#[cfg(not(feature = "alloc"))]
pub type ModMathValue<T> = T;

// Shared rejection-sampled `try_random_mod` body for the modmath
// backend. Called from both the alloc-side `ModMathValue<T>` newtype
// impl and the no-alloc `T` impl below — the only difference is the
// wrapping function applied to the sampled `T` before the modulus
// check.
//
// **Critical: mask the sampled candidate down to `modulus.bits()`
// bits before checking.** When the modulus is `lz` bits narrower
// than `T`'s container width, an unmasked sampler's acceptance rate
// is ~2⁻ˡᶻ and `MAX_TRIES = 128` would exhaust almost every time.
// After masking to `modulus.bits()` bits, we sample from `[0, 2^k)`
// where the modulus's top bit is set, so acceptance is ≥ 50%.
//
// See the `TryRandomMod` trait doc for the CT-property discussion.
#[cfg(feature = "modmath")]
fn try_random_mod_masked<R, T, W, F>(
    rng: &mut R,
    modulus_bits: u32,
    leading_zero_bits: u32,
    modulus: &W,
    wrap: F,
) -> Result<W>
where
    R: rand_core::TryCryptoRng + ?Sized,
    T: FixedWidthUnsignedInt,
    W: PartialOrd,
    F: Fn(T) -> W,
{
    let zero_bytes = (leading_zero_bits / 8) as usize;
    let zero_bits_in_next = (leading_zero_bits % 8) as u8;

    const MAX_TRIES: u32 = 128;
    let mut bytes = <T as FixedWidthUnsignedInt>::Bytes::default();
    // The `Bytes` holder is capacity-width, but the modulus operates at
    // `modulus_bits` (its `bits_precision`, always a whole number of
    // limbs). Sample only the trailing `window_bytes` (big-endian: the
    // low-order bytes): the mask (`leading_zero_bits` = the modulus's own
    // headroom) is then relative to the modulus width, so acceptance is
    // >= 50% even when the modulus is much narrower than the capacity,
    // and parsing just that window yields a candidate at `len ==
    // modulus.len` — width-consistent with the field it feeds rather than
    // a capacity-width operand. For a full-width modulus (`modulus_bits ==
    // capacity`) the window is the whole buffer, so the deployment path is
    // unchanged.
    let window_bytes = (modulus_bits as usize).div_ceil(8);
    let lo = bytes.as_ref().len().saturating_sub(window_bytes);
    for _ in 0..MAX_TRIES {
        rng.try_fill_bytes(bytes.as_mut()).map_err(|_| Error::Rng)?;
        // Big-endian within the window: mask the leading bytes of the
        // window. `skip(lo)` / `get_mut(lo + …)` keep the accesses
        // bounds-check-free (folded into the iterator / `Some` arm), same
        // discipline as the panic-free audit requires elsewhere.
        let buf = bytes.as_mut();
        for byte in buf.iter_mut().skip(lo).take(zero_bytes) {
            *byte = 0;
        }
        if zero_bits_in_next > 0 {
            if let Some(b) = buf.get_mut(lo + zero_bytes) {
                *b &= 0xFFu8 >> zero_bits_in_next;
            }
        }
        let window = bytes.as_ref().get(lo..).ok_or(Error::Internal)?;
        // `from_be_slice`, not the `Bytes`-holder `try_from_be_bytes_vartime`:
        // its output width is the window length — the (public) modulus
        // width — so on the runtime-length carrier `r` lands at the field
        // width the blinded arithmetic needs, rather than padded to
        // capacity. `window.len()` is derived from `modulus_bits`, never
        // from `r`'s bytes, so `r`'s width leaks nothing. On a fixed-width
        // carrier it's the same value zero-extended to capacity (a no-op).
        let candidate = <T as FromByteSlice>::from_be_slice(window).map_err(|_| Error::Internal)?;
        let wrapped = wrap(candidate);
        if wrapped < *modulus {
            return Ok(wrapped);
        }
    }
    Err(Error::Internal)
}

#[cfg(feature = "alloc")]
impl<T> crate::traits::modular::TryRandomMod for ModMathValue<T>
where
    T: FixedWidthUnsignedInt + PartialOrd,
{
    fn try_random_mod<R>(rng: &mut R, modulus: &Self) -> Result<Self>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let container_bits = <T as FixedWidthUnsignedInt>::bits_precision(&modulus.0);
        let leading_zero_bits = <T as FixedWidthUnsignedInt>::leading_zeros(&modulus.0);
        if leading_zero_bits >= container_bits {
            return Err(Error::InvalidModulus);
        }
        try_random_mod_masked::<R, T, _, _>(
            rng,
            container_bits,
            leading_zero_bits,
            modulus,
            wrap_value::<T>,
        )
    }
}

#[cfg(not(feature = "alloc"))]
impl<T> crate::traits::modular::TryRandomMod for T
where
    T: FixedWidthUnsignedInt + PartialOrd,
{
    fn try_random_mod<R>(rng: &mut R, modulus: &Self) -> Result<Self>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let container_bits = <T as FixedWidthUnsignedInt>::bits_precision(modulus);
        let leading_zero_bits = <T as FixedWidthUnsignedInt>::leading_zeros(modulus);
        if leading_zero_bits >= container_bits {
            return Err(Error::InvalidModulus);
        }
        try_random_mod_masked::<R, T, T, _>(rng, container_bits, leading_zero_bits, modulus, |x| x)
    }
}

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

impl<T: ModMathInt + HasPersonality<P = Nct>> ModMathParams<T, Nct> {
    pub fn new(modulus: T) -> Result<Self> {
        let field = ModmathField::<T, Nct>::new(modulus).ok_or(Error::InvalidModulus)?;
        let modulus_odd = Odd::new(wrap_value(modulus)).ok_or(Error::InvalidModulus)?;
        Ok(Self { field, modulus_odd })
    }
}

impl<T: ModMathIntCt + HasPersonality<P = Ct>> ModMathParams<T, Ct> {
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
    T: ModMathInt + HasPersonality<P = Nct>,
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
    T: ModMathInt + HasPersonality<P = Nct>,
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
    T: ModMathIntCt + HasPersonality<P = Ct>,
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
    T: ModMathIntCt + HasPersonality<P = Ct>,
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

impl<T: ModMathInt + HasPersonality<P = Nct>> IntoMontyForm<ModMathParams<T, Nct>>
    for ModMathForm<T, Nct>
{
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

impl<T: ModMathInt + HasPersonality<P = Nct>> ModMathForm<T, Nct> {
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

impl<T: ModMathInt + HasPersonality<P = Nct>> Pow<ModMathParams<T, Nct>> for ModMathForm<T, Nct> {
    fn pow(&self, exp: &ModMathValue<T>) -> Self {
        let result_mont = self.pow_loop(unwrap_value(exp));
        Self {
            integer_mont: wrap_value(result_mont),
            params: self.params.clone(),
        }
    }
}

impl<T: ModMathInt + HasPersonality<P = Nct>> PowBoundedExp<ModMathParams<T, Nct>>
    for ModMathForm<T, Nct>
{
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

impl<T: ModMathInt + HasPersonality<P = Nct>> ModulusParams for ModMathParams<T, Nct> {
    type Modulus = ModMathValue<T>;
    type MontgomeryForm = ModMathForm<T, Nct>;

    fn modulus(&self) -> &Odd<Self::Modulus> {
        &self.modulus_odd
    }

    fn bits_precision(&self) -> u32 {
        FixedWidthUnsignedInt::bits_precision(self.field.modulus())
    }
}

impl<T: ModMathIntCt + HasPersonality<P = Ct>> IntoMontyForm<ModMathParams<T, Ct>>
    for ModMathForm<T, Ct>
{
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

impl<T: ModMathIntCt + HasPersonality<P = Ct>> ModMathForm<T, Ct> {
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

impl<T: ModMathIntCt + HasPersonality<P = Ct>> Pow<ModMathParams<T, Ct>> for ModMathForm<T, Ct> {
    fn pow(&self, exp: &ModMathValue<T>) -> Self {
        let result_mont = self.pow_loop_ct(unwrap_value(exp));
        Self {
            integer_mont: wrap_value(result_mont),
            params: self.params.clone(),
        }
    }
}

impl<T: ModMathIntCt + HasPersonality<P = Ct>> PowBoundedExp<ModMathParams<T, Ct>>
    for ModMathForm<T, Ct>
{
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

// CT modular inverse for RSA-blinding on the modmath backend. Routes
// to modmath's `Field<T, Ct>::inv_safegcd_ct` (Bernstein-Yang). The
// modulus may fill the carrier's full width; `None` means the value
// is not coprime with `n` (astronomically rare, retryable).
impl<T> crate::traits::modular::InvertCt<ModMathParams<T, Ct>> for ModMathForm<T, Ct>
where
    T: ModMathIntCt
        + HasPersonality<P = Ct>
        + modmath_cios::CiosRowOps
        + core::ops::BitOr<Output = T>,
    <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
{
    fn invert_ct(&self) -> Option<Self> {
        let field = self.params.field();
        let residue = field.residue_from_mont(unwrap_value(&self.integer_mont));
        let ct_option = field.inv_safegcd_ct(&residue);
        ct_option.into_option().map(|inv_res| Self {
            integer_mont: wrap_value(*inv_res.mont_value()),
            params: self.params.clone(),
        })
    }
}

// CT Montgomery multiplication. Both operands share this
// `ModMathParams` (invariant, not type-checked). Routes to modmath's
// `Field<T, Ct>::mul` — the CIOS-Ct primitive, branchless in both
// inputs.
impl<T: ModMathIntCt + HasPersonality<P = Ct>> crate::traits::modular::MulCt<ModMathParams<T, Ct>>
    for ModMathForm<T, Ct>
{
    fn mul_ct(&self, rhs: &Self) -> Self {
        // Guard: MulCt's precondition is that both operands share the
        // same modulus. `debug_assert_eq!` would need `T: Debug` for
        // the failure message; use `debug_assert!` with a fixed
        // message to avoid widening the trait bound just for a
        // debug-only check.
        debug_assert!(
            self.params.modulus_odd == rhs.params.modulus_odd,
            "MulCt operands must share the same modulus"
        );
        let field = self.params.field();
        let lhs_res = field.residue_from_mont(unwrap_value(&self.integer_mont));
        let rhs_res = field.residue_from_mont(unwrap_value(&rhs.integer_mont));
        let product = field.mul(&lhs_res, &rhs_res);
        Self {
            integer_mont: wrap_value(*product.mont_value()),
            params: self.params.clone(),
        }
    }
}

impl<T: ModMathIntCt + HasPersonality<P = Ct>> ModulusParams for ModMathParams<T, Ct> {
    type Modulus = ModMathValue<T>;
    type MontgomeryForm = ModMathForm<T, Ct>;

    fn modulus(&self) -> &Odd<Self::Modulus> {
        &self.modulus_odd
    }

    fn bits_precision(&self) -> u32 {
        FixedWidthUnsignedInt::bits_precision(self.field.modulus())
    }
}

// Opt the Ct personality into the CT-encrypt gate. Deliberately no
// impl for `ModMathParams<T, Nct>` — Nct exponentiation is vartime in
// the base, so `NctPublicKey`-derived encrypting keys fail the encrypt
// trait bound at compile time. See
// `crate::traits::modular::CtModulusParams`.
impl<T: ModMathIntCt + HasPersonality<P = Ct>> crate::traits::modular::sealed::CtModulusParamsSealed
    for ModMathParams<T, Ct>
{
}
impl<T: ModMathIntCt + HasPersonality<P = Ct>> crate::traits::modular::CtModulusParams
    for ModMathParams<T, Ct>
{
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use const_num_traits::Ct;
    use fixed_bigint::FixedUInt;
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
            ModMathParams::<U512, const_num_traits::Nct>::new(n).unwrap(),
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
// Gated independently of the alloc block above so they compile and
// run in no_alloc mode.
#[cfg(test)]
mod private_op_tests {
    use super::*;
    use const_num_traits::Ct;
    use fixed_bigint::FixedUInt;

    type SmallUCt = FixedUInt<u8, 64, Ct>;

    // ── Carrier-generic toy tests ──────────────────────────────────
    //
    // Every test below is written as a `fn inner<T>()` over the integer
    // carrier and then instantiated for each backend, mirroring the
    // per-carrier pattern used in fixed-bigint. `SmallUCt` is the
    // fixed-width reference; `HeaplessCt` is the runtime-length carrier
    // the `bigint-heapless-runtime-len` experiment adopts. Tests that
    // pass on both call `both::<…>()`; tests that currently fail on the
    // heapless carrier for a known upstream reason run the reference
    // inline and gate the heapless instantiation behind `#[ignore]`.
    type HeaplessCt = fixed_bigint::HeaplessBigInt<u8, 64, Ct>;

    // The full carrier bound for the CT sign+blind path: enough for
    // `ModMathParams<T, Ct>` and its `MontgomeryForm` to satisfy
    // `Pow + PowBoundedExp + InvertCt + MulCt`, and for `T` /
    // `ModMathValue<T>` to satisfy `TryRandomMod`.
    trait TestCt:
        super::ModMathIntCt
        + HasPersonality<P = Ct>
        + modmath_cios::CiosRowOps
        + core::ops::BitOr<Output = Self>
        + core::fmt::Debug
    where
        <Self as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
    {
    }
    impl<T> TestCt for T
    where
        T: super::ModMathIntCt
            + HasPersonality<P = Ct>
            + modmath_cios::CiosRowOps
            + core::ops::BitOr<Output = T>
            + core::fmt::Debug,
        <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
    {
    }

    // n = 35 = 5 · 7, φ(n) = 24. e = 5, d = 29 (since 5·29 = 145 ≡ 1 mod 24).
    // m = 2 → c = 2^5 mod 35 = 32 → m_recovered = 32^29 mod 35 = 2.
    fn toy_params<T: TestCt>() -> ModMathParams<T, Ct>
    where
        <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
    {
        ModMathParams::<T, Ct>::new(
            <T as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&[35]).unwrap(),
        )
        .unwrap()
    }

    // A 512-bit odd modulus used by the `sign_into` defensive-error
    // tests below — they need the actual modulus bit-length (which
    // `sign_into` checks) to match `SMALL_K * 8`
    // so `k` passes the up-front width check and the specific error
    // path (small buffer, wrong hash length, etc.) is what fires.
    // Value is `2^511 + 1`: MSB set, LSB=1 (odd). (`FixedUInt<u8, 64>`
    // only — this shape drives the fixed-width defensive checks.)
    fn toy_params_wide() -> ModMathParams<SmallUCt, Ct> {
        let mut bytes = [0u8; 64];
        bytes[0] = 0x80;
        bytes[63] = 0x01;
        let n = <SmallUCt as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&bytes).unwrap();
        ModMathParams::<SmallUCt, Ct>::new(n).unwrap()
    }

    #[test]
    fn rsa_private_op_round_trip() {
        fn inner<T: TestCt>()
        where
            <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
        {
            let n_params = toy_params::<T>();
            let c = wrap_value(T::from(32u8));
            let d = wrap_value(T::from(29u8));
            let expected = wrap_value(T::from(2u8));
            let recovered = crate::algorithms::rsa::rsa_private_op(&c, &d, &n_params);
            assert_eq!(recovered, expected);
        }
        inner::<SmallUCt>();
        inner::<HeaplessCt>();
    }

    // Blinded RSA private op must produce the same plaintext as the
    // unblinded op, regardless of the caller-supplied `r`. Toy modulus
    // n = 35, e = 5, d = 29, c = 32; expected m = 2. r = 6 (coprime
    // with 35). The blinded body should recover m = 2 the same way
    // rsa_private_op does.
    fn blinded_matches_unblinded_inner<T: TestCt>()
    where
        <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
    {
        let n_params = toy_params::<T>();
        let c = wrap_value(T::from(32u8));
        let d = wrap_value(T::from(29u8));
        let e = wrap_value(T::from(5u8));
        let r = wrap_value(T::from(6u8));
        let expected = wrap_value(T::from(2u8));
        let recovered =
            crate::algorithms::rsa::rsa_private_op_blinded(&r, &c, &d, &e, &n_params).unwrap();
        assert_eq!(recovered, expected);
    }
    #[test]
    fn rsa_private_op_blinded_matches_unblinded() {
        blinded_matches_unblinded_inner::<SmallUCt>();
        blinded_matches_unblinded_inner::<HeaplessCt>();
    }

    // Blinded op must fail if `r` shares a factor with `n` — the inverse
    // doesn't exist, `invert_ct` returns None, and the primitive returns
    // Err. Toy: n = 35 = 5·7, r = 5 (shares factor with n). No retry at
    // the primitive level — caller policy. Runs on both carriers: 5 is
    // genuinely non-invertible mod 35 on each, so `invert_ct` returns
    // None for the *right* reason (not vacuously).
    #[test]
    fn rsa_private_op_blinded_rejects_non_coprime_r() {
        fn inner<T: TestCt>()
        where
            <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
        {
            let n_params = toy_params::<T>();
            let c = wrap_value(T::from(32u8));
            let d = wrap_value(T::from(29u8));
            let e = wrap_value(T::from(5u8));
            let r_bad = wrap_value(T::from(5u8)); // shares factor 5 with n = 35
            let result =
                crate::algorithms::rsa::rsa_private_op_blinded(&r_bad, &c, &d, &e, &n_params);
            assert!(result.is_err());
        }
        inner::<SmallUCt>();
        inner::<HeaplessCt>();
    }

    // Full-stack blinded op with RNG-driven `r` sampling. Same toy
    // setup as the unblinded round-trip; the wrapper samples r via
    // TryRandomMod, retries on non-coprime, then verifies m^e ≡ c
    // before returning. For toy n=35, non-coprime probability per
    // draw is ~31% — the 10-retry cap gives failure prob ~8e-6, so
    // the test is reliable.
    fn and_check_blinded_round_trip_inner<T: TestCt>()
    where
        <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
    {
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;

        let n_params = toy_params::<T>();
        let c = wrap_value(T::from(32u8));
        let d = wrap_value(T::from(29u8));
        let e = wrap_value(T::from(5u8));
        let expected = wrap_value(T::from(2u8));
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let recovered = crate::algorithms::rsa::rsa_private_op_and_check_blinded(
            &mut rng, &c, &d, &e, &n_params,
        )
        .unwrap();
        assert_eq!(recovered, expected);
    }
    #[test]
    fn rsa_private_op_and_check_blinded_round_trip() {
        and_check_blinded_round_trip_inner::<SmallUCt>();
        and_check_blinded_round_trip_inner::<HeaplessCt>();
    }

    // Uses toy_params_wide's 512-bit modulus (`2^511 + 1`) so the
    // acceptance rate is essentially 50% (top bit set) and 128-tries
    // doesn't get exhausted. Sampler-only path — no inverse — so it
    // runs on both carriers.
    fn try_random_mod_below_modulus_inner<T: TestCt>(n: ModMathValue<T>)
    where
        <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
    {
        use crate::traits::modular::TryRandomMod;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let mut samples = [ModMathValue::<T>::from(0u8); 16];
        for slot in samples.iter_mut() {
            let r = ModMathValue::<T>::try_random_mod(&mut rng, &n).unwrap();
            assert!(r < n, "sample must be < modulus");
            *slot = r;
        }
        let first = samples[0];
        assert!(
            samples.iter().any(|s| *s != first),
            "samples are trivially all equal — RNG or sampler broken"
        );
    }
    #[test]
    fn try_random_mod_modmath_stays_below_modulus() {
        // 2^511 + 1 in each carrier.
        let mut bytes = [0u8; 64];
        bytes[0] = 0x80;
        bytes[63] = 0x01;
        let nf = <SmallUCt as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&bytes).unwrap();
        try_random_mod_below_modulus_inner::<SmallUCt>(wrap_value(nf));
        let nh = <HeaplessCt as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&bytes).unwrap();
        try_random_mod_below_modulus_inner::<HeaplessCt>(wrap_value(nh));
    }

    // An unmasked sampler's acceptance rate against a modulus whose
    // value is many bits narrower than its width is ~2⁻ˡᶻ, blowing the
    // 128-tries cap. Masking must let sampling succeed even when the
    // value occupies only ~6 bits of a full-width modulus — this is
    // `toy_params()` (n = 35, built at full carrier width `len == CAP`),
    // so here `bits_precision` equals the sample-buffer width and the
    // ~6-bit *value* is the narrow quantity the mask brings the candidate
    // down to. The complementary case — a modulus narrow in *width*
    // (`len < CAP`), where the window is a strict sub-slice of the buffer
    // — is `try_random_mod_accepts_narrow_modulus`.
    #[test]
    fn try_random_mod_modmath_succeeds_on_narrow_modulus_wide_carrier() {
        fn inner<T: TestCt>()
        where
            <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
        {
            use crate::traits::modular::TryRandomMod;
            use rand::rngs::ChaCha8Rng;
            use rand_core::SeedableRng;

            let n_params = toy_params::<T>();
            let n = *n_params.modulus().as_ref();
            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            for _ in 0..64 {
                let r = ModMathValue::<T>::try_random_mod(&mut rng, &n).unwrap();
                assert!(r < n);
            }
        }
        inner::<SmallUCt>();
        inner::<HeaplessCt>();
    }

    #[test]
    fn rsa_private_op_and_check_round_trip() {
        fn inner<T: TestCt>()
        where
            <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
        {
            let n_params = toy_params::<T>();
            let c = wrap_value(T::from(32u8));
            let d = wrap_value(T::from(29u8));
            let e = wrap_value(T::from(5u8));
            let expected = wrap_value(T::from(2u8));
            let recovered =
                crate::algorithms::rsa::rsa_private_op_and_check(&c, &d, &e, &n_params).unwrap();
            assert_eq!(recovered, expected);
        }
        inner::<SmallUCt>();
        inner::<HeaplessCt>();
    }

    // Verify the `InvertCt` primitive on the modmath backend against
    // a known-answer inverse. n = 35, 3⁻¹ mod 35 = 12 (since 3·12 = 36 ≡ 1).
    // Exercises the modmath `Field::inv_safegcd_ct` bridge.
    fn invert_ct_known_answer_inner<T: TestCt>()
    where
        <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
    {
        use crate::traits::modular::{IntoMontyForm, InvertCt, PowBoundedExp};
        let n_params = toy_params::<T>();
        let three = wrap_value(T::from(3u8));
        let mont_three = ModMathForm::<T, Ct>::from_reduced(three, &n_params);
        let mont_inv = mont_three.invert_ct().expect("3 is coprime to 35");
        let recovered = PowBoundedExp::<ModMathParams<T, Ct>>::retrieve(&mont_inv);
        assert_eq!(recovered, wrap_value(T::from(12u8)));
    }
    // `invert_ct` works on both carriers at every width — the toy `n = 35`
    // here and the 2048-bit full-CAP deployment modulus exercised
    // end-to-end by the `heapless_bigint_smoke` blinded-sign test (which
    // passes; the earlier `inv_safegcd_ct` None-at-u32x64 bug was fixed
    // upstream in the alpha.21 / cios.8 chain).
    #[test]
    fn invert_ct_modmath_known_answer() {
        invert_ct_known_answer_inner::<SmallUCt>();
        invert_ct_known_answer_inner::<HeaplessCt>();
    }

    // Verify the `MulCt` primitive on the modmath backend against a
    // known-answer product. n = 35, 3·12 = 36 ≡ 1 (mod 35). Exercises
    // the modmath `Field::mul` bridge; also completes the round-trip
    // with `InvertCt` — inverting 3 and multiplying back gives 1.
    fn mul_ct_inverse_round_trip_inner<T: TestCt>()
    where
        <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
    {
        use crate::traits::modular::{IntoMontyForm, InvertCt, MulCt, PowBoundedExp};
        let n_params = toy_params::<T>();
        let three = wrap_value(T::from(3u8));
        let mont_three = ModMathForm::<T, Ct>::from_reduced(three, &n_params);
        let mont_inv = mont_three.invert_ct().expect("3 is coprime to 35");
        let product = mont_three.mul_ct(&mont_inv);
        let recovered = PowBoundedExp::<ModMathParams<T, Ct>>::retrieve(&product);
        assert_eq!(recovered, wrap_value(T::from(1u8)));
    }
    #[test]
    fn mul_ct_modmath_inverse_round_trip() {
        mul_ct_inverse_round_trip_inner::<SmallUCt>();
        mul_ct_inverse_round_trip_inner::<HeaplessCt>();
    }

    // ── Sub-capacity operation: a runtime-length modulus narrower than
    // the carrier capacity (`len < CAP`). This is the deployment target
    // for one binary serving multiple key sizes — e.g. a 4096-bit-CAP
    // `HeaplessBigInt` operating on 1024/2048-bit keys at their own width
    // rather than padded to capacity. `HeaplessCt` is `u8 × 64` (512-bit
    // CAP); a natural-width `n = 35` (built with the inherent slice
    // constructor) has `bits_precision = 8`, so `len = 1 << 64`.

    // The rejection sampler must accept on a narrow modulus. Its buffer is
    // capacity-width, so the mask/window has to be taken relative to the
    // modulus width — otherwise `leading_zeros(modulus)` (headroom within
    // the modulus width, here 0) masks nothing of a 512-bit buffer and the
    // candidate is ~2^512 ≫ 35, rejected every try.
    #[test]
    fn try_random_mod_accepts_narrow_modulus() {
        use crate::traits::modular::TryRandomMod;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        let n_nat = HeaplessCt::from_be_bytes(&[35]); // inherent -> len 1
        assert_eq!(
            const_num_traits::BitsPrecision::bits_precision(&n_nat),
            8,
            "modulus must be at its natural width, not padded to CAP"
        );
        let n = wrap_value(n_nat);
        let mut rng = ChaCha8Rng::from_seed([7; 32]);
        for _ in 0..16 {
            let r = <ModMathValue<HeaplessCt> as TryRandomMod>::try_random_mod(&mut rng, &n)
                .expect("sampler must accept on a narrow modulus");
            assert!(r < n, "sampled r must be < modulus");
        }
    }

    // The field itself operates correctly at a narrow width: plain op and
    // blinded op both recover m = 2 when every operand shares the modulus
    // width. (c = 32, d = 29, e = 5, r = 6, all len 1.)
    #[test]
    fn narrow_modulus_private_ops_round_trip() {
        let n_params =
            ModMathParams::<HeaplessCt, Ct>::new(HeaplessCt::from_be_bytes(&[35])).unwrap();
        let c = wrap_value(HeaplessCt::from(32u8));
        let d = wrap_value(HeaplessCt::from(29u8));
        let e = wrap_value(HeaplessCt::from(5u8));
        let two = HeaplessCt::from(2u8);

        let m = crate::algorithms::rsa::rsa_private_op(&c, &d, &n_params);
        assert_eq!(into_inner(m), two);

        let r_nat = wrap_value(HeaplessCt::from(6u8)); // coprime with 35, len 1
        let blinded =
            crate::algorithms::rsa::rsa_private_op_blinded(&r_nat, &c, &d, &e, &n_params).unwrap();
        assert_eq!(into_inner(blinded), two);
    }

    // Full sampled blinded op on a narrow modulus: the sampler now parses
    // its modulus-width window with `FromByteSlice::from_be_slice`, so the
    // sampled `r` lands at the field width and the blinded arithmetic (and
    // verify-after-sign) closes. This is the end-to-end sub-capacity proof
    // — the randomized sign path a `len < CAP` deployment actually runs.
    #[test]
    fn narrow_modulus_sampled_blinded_op() {
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        let n_params =
            ModMathParams::<HeaplessCt, Ct>::new(HeaplessCt::from_be_bytes(&[35])).unwrap();
        let c = wrap_value(HeaplessCt::from(32u8));
        let d = wrap_value(HeaplessCt::from(29u8));
        let e = wrap_value(HeaplessCt::from(5u8));
        let mut rng = ChaCha8Rng::from_seed([9; 32]);
        let recovered = crate::algorithms::rsa::rsa_private_op_and_check_blinded(
            &mut rng, &c, &d, &e, &n_params,
        )
        .unwrap();
        assert_eq!(into_inner(recovered), HeaplessCt::from(2u8));
    }

    #[test]
    fn rsa_private_op_and_check_rejects_wrong_exponent() {
        fn inner<T: TestCt>()
        where
            <T as modmath_cios::CiosRowOps>::Word: const_num_traits::CtParity,
        {
            // Same modulus + e, wrong `d` (11 vs 29). The recovered `m`
            // won't re-encrypt back to `c`, so the check should fail.
            let n_params = toy_params::<T>();
            let c = wrap_value(T::from(32u8));
            let bad_d = wrap_value(T::from(11u8));
            let e = wrap_value(T::from(5u8));
            let result =
                crate::algorithms::rsa::rsa_private_op_and_check(&c, &bad_d, &e, &n_params);
            assert!(result.is_err());
        }
        inner::<SmallUCt>();
        inner::<HeaplessCt>();
    }

    // 2048-bit RSA keypair fixture — same `(n, e=65537, d)` used in
    // `algorithms::rsa::tests::recover_primes_works`, duplicated here
    // so the no-alloc test path can roundtrip-sign. `e` is rendered as
    // 3-byte BE (`0x010001`) and resized into `U2048` at test time.
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

    #[test]
    fn pss_sign_into_round_trip_2048_sha1() {
        use crate::algorithms::pss::{emsa_pss_verify, sign_into};
        use crate::traits::PublicKeyParts;
        use digest::Digest;
        use sha1::Sha1;

        type U2048 = FixedUInt<u8, 256, Ct>;
        const K: usize = 256;
        const KEY_BITS: usize = 2048;

        let key = public_key_ct_from_be_bytes::<U2048>(&N_2048, 65537).unwrap();
        let d = wrap_value(
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&D_2048).unwrap(),
        );
        let e = wrap_value(
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&[0x01, 0x00, 0x01])
                .unwrap(),
        );

        let digest = [0xAAu8; 20];
        let salt: &[u8] = &[]; // empty salt → deterministic encoding
        let mut hash = Sha1::new();

        let mut em_storage = [0u8; K];
        let mut sig_storage = [0u8; K];
        let sig = sign_into(
            key.n_params(),
            &d,
            &e,
            &digest,
            salt,
            K,
            &mut hash,
            &mut em_storage,
            &mut sig_storage,
        )
        .unwrap();
        assert_eq!(sig.len(), K);

        // Roundtrip via public op: `sig^e mod n` must yield a valid PSS-encoded
        // EM for `(digest, salt)`. `emsa_pss_verify` modifies `em` in place
        // (MGF unmask), so copy the recovered bytes into a mutable buffer.
        let recovered = public_key_op_ct(&key, sig).unwrap();
        let mut em_copy = [0u8; K];
        em_copy.copy_from_slice(recovered.as_ref());
        let mut verify_hash = Sha1::new();
        emsa_pss_verify(
            &digest,
            &mut em_copy,
            Some(salt.len()),
            &mut verify_hash,
            KEY_BITS,
        )
        .unwrap();
    }

    // Local alias for `rsa_public_op_ct` — keeps the test's call-site short.
    fn public_key_op_ct<T>(
        key: &crate::key::GenericRsaPublicKey<ModMathValue<T>, ModMathParams<T, Ct>>,
        input: &[u8],
    ) -> Result<<ModMathValue<T> as UnsignedModularInt>::Bytes>
    where
        T: ModMathIntCt + HasPersonality<P = Ct>,
    {
        crate::modmath_support::rsa_public_op_ct(key, input)
    }

    // ─── defensive-error tests for `sign_into` upfront checks ───────────
    //
    // These tests trip `sign_into`'s fast-fail guards. None reach the
    // RSA exponentiation, so `d`/`e` can be dummy values
    // and the toy `SmallUCt` (512-bit) `n_params` is sufficient.

    fn dummy_de() -> (ModMathValue<SmallUCt>, ModMathValue<SmallUCt>) {
        (
            wrap_value(SmallUCt::from(1u8)),
            wrap_value(SmallUCt::from(1u8)),
        )
    }

    // SmallUCt = FixedUInt<u8, 64, Ct> → bits_precision = 512 → k = 64.
    const SMALL_K: usize = 64;

    #[test]
    fn pkcs1v15_sign_into_rejects_wrong_k() {
        use crate::algorithms::pkcs1v15::sign_into;
        let n_params = toy_params();
        let (d, e) = dummy_de();
        let mut em = [0u8; SMALL_K];
        let mut sig = [0u8; SMALL_K];
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &[],
            &[0u8; 20],
            SMALL_K - 1, // wrong: should be SMALL_K
            &mut em,
            &mut sig,
        );
        assert!(matches!(result, Err(Error::InvalidArguments)));
    }

    #[test]
    fn pkcs1v15_sign_into_rejects_small_sig_storage() {
        use crate::algorithms::pkcs1v15::sign_into;
        let n_params = toy_params_wide();
        let (d, e) = dummy_de();
        let mut em = [0u8; SMALL_K];
        let mut sig = [0u8; SMALL_K - 1]; // one byte short
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &[],
            &[0u8; 20],
            SMALL_K,
            &mut em,
            &mut sig,
        );
        assert!(matches!(result, Err(Error::OutputBufferTooSmall)));
    }

    #[test]
    fn pkcs1v15_sign_into_propagates_message_too_long() {
        // prefix + hashed + 11 > k → `pkcs1v15_sign_pad_into` returns
        // MessageTooLong. Confirms errors from the padding step bubble up.
        use crate::algorithms::pkcs1v15::sign_into;
        let n_params = toy_params_wide();
        let (d, e) = dummy_de();
        let mut em = [0u8; SMALL_K];
        let mut sig = [0u8; SMALL_K];
        let oversize_prefix = [0u8; SMALL_K]; // 64-byte prefix alone exceeds k - 11
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &oversize_prefix,
            &[0u8; 20],
            SMALL_K,
            &mut em,
            &mut sig,
        );
        assert!(matches!(result, Err(Error::MessageTooLong)));
    }

    #[test]
    fn pss_sign_into_rejects_wrong_k() {
        use crate::algorithms::pss::sign_into;
        use digest::Digest;
        use sha1::Sha1;
        let n_params = toy_params_wide();
        let (d, e) = dummy_de();
        let mut em = [0u8; SMALL_K];
        let mut sig = [0u8; SMALL_K];
        let mut hash = Sha1::new();
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &[0u8; 20],
            &[],
            SMALL_K - 1, // wrong
            &mut hash,
            &mut em,
            &mut sig,
        );
        assert!(matches!(result, Err(Error::InvalidArguments)));
    }

    #[test]
    fn pss_sign_into_rejects_small_sig_storage() {
        use crate::algorithms::pss::sign_into;
        use digest::Digest;
        use sha1::Sha1;
        let n_params = toy_params_wide();
        let (d, e) = dummy_de();
        let mut em = [0u8; SMALL_K];
        let mut sig = [0u8; SMALL_K - 1];
        let mut hash = Sha1::new();
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &[0u8; 20],
            &[],
            SMALL_K,
            &mut hash,
            &mut em,
            &mut sig,
        );
        assert!(matches!(result, Err(Error::OutputBufferTooSmall)));
    }

    #[test]
    fn pss_sign_into_rejects_small_em_storage() {
        use crate::algorithms::pss::sign_into;
        use digest::Digest;
        use sha1::Sha1;
        let n_params = toy_params_wide();
        let (d, e) = dummy_de();
        // em_bits = key_bits - 1 = 511 → em_len = 64. Pass 63 to fail.
        let mut em = [0u8; SMALL_K - 1];
        let mut sig = [0u8; SMALL_K];
        let mut hash = Sha1::new();
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &[0u8; 20],
            &[],
            SMALL_K,
            &mut hash,
            &mut em,
            &mut sig,
        );
        assert!(matches!(result, Err(Error::OutputBufferTooSmall)));
    }

    #[test]
    fn pss_sign_into_rejects_wrong_hash_length() {
        // emsa_pss_encode_into returns InputNotHashed when m_hash.len()
        // != hash output size. Confirms errors from the encode step bubble up.
        use crate::algorithms::pss::sign_into;
        use digest::Digest;
        use sha1::Sha1;
        let n_params = toy_params_wide();
        let (d, e) = dummy_de();
        let mut em = [0u8; SMALL_K];
        let mut sig = [0u8; SMALL_K];
        let mut hash = Sha1::new();
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &[0u8; 21], // SHA-1 produces 20 bytes, not 21
            &[],
            SMALL_K,
            &mut hash,
            &mut em,
            &mut sig,
        );
        assert!(matches!(result, Err(Error::InputNotHashed)));
    }

    // `sign_into`'s `k` check must use the actual modulus bit-length,
    // not the container's `bits_precision()`, otherwise a shorter
    // modulus stored in a wider container spuriously rejects the only
    // valid `k`.
    #[test]
    fn pkcs1v15_sign_into_k_uses_modulus_bits_not_container() {
        use crate::algorithms::pkcs1v15::sign_into;
        // 128-byte (1024-bit) container storing a ~512-bit modulus.
        type WideUCt = FixedUInt<u8, 128, Ct>;
        let mut mod_bytes = [0u8; 128];
        mod_bytes[64] = 0x80; // MSB of the low 512 bits
        mod_bytes[127] = 0x01; // LSB odd
        let n = <WideUCt as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&mod_bytes).unwrap();
        let n_params = ModMathParams::<WideUCt, Ct>::new(n).unwrap();
        let d = wrap_value(WideUCt::from(29u8));
        let e = wrap_value(WideUCt::from(5u8));

        const CORRECT_K: usize = 64; // 512 modulus bits div_ceil 8
        const CONTAINER_K: usize = 128; // what `bits_precision()` would say

        // k = modulus_bits.div_ceil(8) must pass the width check even
        // though the container is wider (it then fails later on the
        // toy (d, e) — that's expected and asserted below).
        let mut em = [0u8; CORRECT_K];
        let mut sig = [0u8; CORRECT_K];
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &[],
            &[0u8; 20],
            CORRECT_K,
            &mut em,
            &mut sig,
        );
        assert!(
            !matches!(result, Err(Error::InvalidArguments)),
            "correct k (= modulus_bits.div_ceil(8)) must pass the width check, got {:?}",
            result
        );

        // Container-width k must be rejected — that's the whole point.
        let mut em = [0u8; CONTAINER_K];
        let mut sig = [0u8; CONTAINER_K];
        let result = sign_into(
            &n_params,
            &d,
            &e,
            &[],
            &[0u8; 20],
            CONTAINER_K,
            &mut em,
            &mut sig,
        );
        assert!(matches!(result, Err(Error::InvalidArguments)));
    }

    // ─── PrivateKeyParts smoke tests ─────────────────────────────

    #[test]
    fn pkcs1v15_signing_key_round_trip_2048_sha1() {
        use crate::key::{GenericRsaPrivateKey, GenericRsaPublicKey};
        use crate::pkcs1v15::{GenericSignature, GenericSigningKey, GenericVerifyingKey};
        use digest::Digest;
        use sha1::Sha1;
        use signature::hazmat::PrehashVerifier;

        type U2048 = FixedUInt<u8, 256, Ct>;
        const K: usize = 256;

        let public =
            crate::modmath_support::public_key_ct_from_be_bytes::<U2048>(&N_2048, 65537).unwrap();
        let public_clone: GenericRsaPublicKey<ModMathValue<U2048>, ModMathParams<U2048, Ct>> =
            public.clone();
        let d = wrap_value(
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&D_2048).unwrap(),
        );
        let priv_key = GenericRsaPrivateKey::from_public_and_d(public, d);

        let signing_key = GenericSigningKey::<Sha1, _, _>::new(priv_key);
        let verifying_key = GenericVerifyingKey::<Sha1, _, _>::new(public_clone);

        let msg: &[u8] = b"deterministic test message";
        let mut em_storage = [0u8; K];
        let mut sig_storage = [0u8; K];
        let sig_slice = signing_key
            .try_sign_into(msg, &mut em_storage, &mut sig_storage)
            .unwrap();
        assert_eq!(sig_slice.len(), K);

        // Round-trip: build a `GenericSignature` over the same modulus type
        // and verify against the prehash via the existing verifier.
        let sig_int =
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(sig_slice).unwrap();
        let sig = GenericSignature::from(wrap_value(sig_int));
        let digest = Sha1::digest(msg);
        verifying_key.verify_prehash(&digest, &sig).unwrap();
    }

    #[test]
    fn pkcs1v15_signing_key_rejects_wrong_prehash_length() {
        use crate::key::GenericRsaPrivateKey;
        use crate::pkcs1v15::GenericSigningKey;
        use sha1::Sha1;

        type U2048 = FixedUInt<u8, 256, Ct>;
        const K: usize = 256;

        let public =
            crate::modmath_support::public_key_ct_from_be_bytes::<U2048>(&N_2048, 65537).unwrap();
        let d = wrap_value(
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&D_2048).unwrap(),
        );
        let priv_key = GenericRsaPrivateKey::from_public_and_d(public, d);
        let signing_key = GenericSigningKey::<Sha1, _, _>::new(priv_key);

        let bad_prehash = [0u8; 21]; // SHA-1 outputs 20 bytes, not 21.
        let mut em_storage = [0u8; K];
        let mut sig_storage = [0u8; K];
        let result =
            signing_key.try_sign_prehash_into(&bad_prehash, &mut em_storage, &mut sig_storage);
        assert!(matches!(result, Err(Error::InputNotHashed)));
    }

    #[test]
    fn pss_signing_key_round_trip_2048_sha1() {
        use crate::algorithms::pss::emsa_pss_verify;
        use crate::key::GenericRsaPrivateKey;
        use crate::pss::GenericSigningKey;
        use digest::Digest;
        use sha1::Sha1;

        type U2048 = FixedUInt<u8, 256, Ct>;
        const K: usize = 256;
        const KEY_BITS: usize = 2048;

        let key =
            crate::modmath_support::public_key_ct_from_be_bytes::<U2048>(&N_2048, 65537).unwrap();
        let d = wrap_value(
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&D_2048).unwrap(),
        );
        let priv_key = GenericRsaPrivateKey::from_public_and_d(key.clone(), d);
        // Salt length = 0 → deterministic encoding, easy roundtrip.
        let signing_key = GenericSigningKey::<Sha1, _, _>::new_with_salt_len(priv_key, 0);

        let msg: &[u8] = b"pss-roundtrip test message";
        let digest = Sha1::digest(msg);
        let mut em_storage = [0u8; K];
        let mut sig_storage = [0u8; K];
        let sig_slice = signing_key
            .try_sign_prehash_with_salt_into(&digest, &[], &mut em_storage, &mut sig_storage)
            .unwrap();
        assert_eq!(sig_slice.len(), K);

        // Roundtrip: `sig^e mod n` should yield a valid PSS-encoded EM
        // for `(digest, salt_len=0)`. `emsa_pss_verify` modifies em
        // in place (MGF unmask), so copy first.
        let recovered = public_key_op_ct(&key, sig_slice).unwrap();
        let mut em_copy = [0u8; K];
        em_copy.copy_from_slice(recovered.as_ref());
        let mut verify_hash = Sha1::new();
        emsa_pss_verify(&digest, &mut em_copy, Some(0), &mut verify_hash, KEY_BITS).unwrap();
    }

    // Exact-width blinded sign round trip on the modmath backend:
    // a 2048-bit modulus in exactly `U2048` must blind, invert, and
    // sign successfully — no carrier headroom over the modulus is
    // required.
    #[test]
    fn pss_signing_key_try_sign_prehash_with_rng_into_round_trip_2048_sha1() {
        use crate::algorithms::pss::emsa_pss_verify;
        use crate::key::GenericRsaPrivateKey;
        use crate::pss::GenericSigningKey;
        use digest::Digest;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use sha1::Sha1;

        type U2048 = FixedUInt<u8, 256, Ct>;
        const K: usize = 256;
        const KEY_BITS: usize = 2048;

        let key =
            crate::modmath_support::public_key_ct_from_be_bytes::<U2048>(&N_2048, 65537).unwrap();
        let d = wrap_value(
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&D_2048).unwrap(),
        );
        let priv_key = GenericRsaPrivateKey::from_public_and_d(key.clone(), d);
        // Salt length = 0 → deterministic PSS encoding.
        let signing_key = GenericSigningKey::<Sha1, _, _>::new_with_salt_len(priv_key, 0);

        let msg: &[u8] = b"pss-blinded-roundtrip test message";
        let digest = Sha1::digest(msg);
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let mut em_storage = [0u8; K];
        let mut sig_storage = [0u8; K];
        let mut salt_storage = [0u8; 0];
        let sig_slice = signing_key
            .try_sign_prehash_with_rng_into(
                &mut rng,
                &digest,
                &mut em_storage,
                &mut sig_storage,
                &mut salt_storage,
            )
            .unwrap();
        assert_eq!(sig_slice.len(), K);

        let recovered = public_key_op_ct(&key, sig_slice).unwrap();
        let mut em_copy = [0u8; K];
        em_copy.copy_from_slice(recovered.as_ref());
        let mut verify_hash = Sha1::new();
        emsa_pss_verify(&digest, &mut em_copy, Some(0), &mut verify_hash, KEY_BITS).unwrap();
    }

    #[test]
    fn pss_signing_key_rejects_wrong_prehash_length() {
        use crate::key::GenericRsaPrivateKey;
        use crate::pss::GenericSigningKey;
        use sha1::Sha1;

        type U2048 = FixedUInt<u8, 256, Ct>;
        const K: usize = 256;

        let key =
            crate::modmath_support::public_key_ct_from_be_bytes::<U2048>(&N_2048, 65537).unwrap();
        let d = wrap_value(
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&D_2048).unwrap(),
        );
        let priv_key = GenericRsaPrivateKey::from_public_and_d(key, d);
        let signing_key = GenericSigningKey::<Sha1, _, _>::new_with_salt_len(priv_key, 0);

        let bad_prehash = [0u8; 21]; // SHA-1 is 20 bytes.
        let mut em_storage = [0u8; K];
        let mut sig_storage = [0u8; K];
        let result = signing_key.try_sign_prehash_with_salt_into(
            &bad_prehash,
            &[],
            &mut em_storage,
            &mut sig_storage,
        );
        assert!(matches!(result, Err(Error::InputNotHashed)));
    }

    #[test]
    fn pss_signing_key_rejects_salt_len_mismatch() {
        use crate::key::GenericRsaPrivateKey;
        use crate::pss::GenericSigningKey;
        use sha1::Sha1;

        type U2048 = FixedUInt<u8, 256, Ct>;
        const K: usize = 256;

        let key =
            crate::modmath_support::public_key_ct_from_be_bytes::<U2048>(&N_2048, 65537).unwrap();
        let d = wrap_value(
            <U2048 as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(&D_2048).unwrap(),
        );
        let priv_key = GenericRsaPrivateKey::from_public_and_d(key, d);
        // salt_len configured to 20; supply 16 -> mismatch.
        let signing_key = GenericSigningKey::<Sha1, _, _>::new_with_salt_len(priv_key, 20);

        let prehash = [0u8; 20];
        let wrong_salt = [0u8; 16];
        let mut em_storage = [0u8; K];
        let mut sig_storage = [0u8; K];
        let result = signing_key.try_sign_prehash_with_salt_into(
            &prehash,
            &wrong_salt,
            &mut em_storage,
            &mut sig_storage,
        );
        assert!(matches!(result, Err(Error::InvalidArguments)));
    }

    #[test]
    fn pss_signing_key_satisfies_zeroize() {
        use crate::key::GenericRsaPrivateKey;
        use crate::pss::GenericSigningKey;
        use sha1::Sha1;
        fn assert_zeroize<Z: Zeroize>() {}
        assert_zeroize::<
            GenericSigningKey<Sha1, ModMathValue<SmallUCt>, ModMathParams<SmallUCt, Ct>>,
        >();

        let public =
            crate::modmath_support::public_key_ct_from_be_bytes::<SmallUCt>(&[35u8], 5).unwrap();
        let priv_key =
            GenericRsaPrivateKey::from_public_and_d(public, wrap_value(SmallUCt::from(29u8)));
        let mut signing_key = GenericSigningKey::<Sha1, _, _>::new(priv_key);
        signing_key.zeroize();
    }

    #[test]
    fn pkcs1v15_signing_key_satisfies_zeroize() {
        use crate::key::GenericRsaPrivateKey;
        use crate::pkcs1v15::GenericSigningKey;
        use sha1::Sha1;
        fn assert_zeroize<Z: Zeroize>() {}
        assert_zeroize::<
            GenericSigningKey<Sha1, ModMathValue<SmallUCt>, ModMathParams<SmallUCt, Ct>>,
        >();

        // Construct one and exercise .zeroize() at runtime to confirm the
        // delegation compiles end-to-end.
        let public =
            crate::modmath_support::public_key_ct_from_be_bytes::<SmallUCt>(&[35u8], 5).unwrap();
        let priv_key =
            GenericRsaPrivateKey::from_public_and_d(public, wrap_value(SmallUCt::from(29u8)));
        let mut signing_key = GenericSigningKey::<Sha1, _, _>::new(priv_key);
        signing_key.zeroize();
    }

    #[test]
    fn generic_rsa_private_key_satisfies_traits() {
        // Compile-time assertion: GenericRsaPrivateKey<SmallUCt, ModMathParams<SmallUCt, Ct>>
        // satisfies both PublicKeyParts and PrivateKeyParts at the
        // matching (T, M) substitution. The fn-bound dance below is the
        // standard "type-satisfies-trait" check.
        use crate::key::GenericRsaPrivateKey;
        use crate::traits::keys::{PrivateKeyParts, PublicKeyParts};
        fn assert_pub_parts<K, T>(_: &K)
        where
            T: UnsignedModularInt,
            K: PublicKeyParts<T>,
        {
        }
        fn assert_priv_parts<K, T>(_: &K)
        where
            T: UnsignedModularInt,
            K: PrivateKeyParts<T>,
        {
        }

        // Use the existing public-key constructor for the pubkey side,
        // then attach a dummy d.
        let public =
            crate::modmath_support::public_key_ct_from_be_bytes::<SmallUCt>(&[35u8], 5).unwrap();
        let key = GenericRsaPrivateKey::from_public_and_d(public, wrap_value(SmallUCt::from(29u8)));

        assert_pub_parts::<_, ModMathValue<SmallUCt>>(&key);
        assert_priv_parts::<_, ModMathValue<SmallUCt>>(&key);

        // Round-trip: accessors return the values we constructed it with.
        assert_eq!(PrivateKeyParts::d(&key), &wrap_value(SmallUCt::from(29u8)));
        assert_eq!(key.as_public().e(), &wrap_value(SmallUCt::from(5u8)));
    }
}
