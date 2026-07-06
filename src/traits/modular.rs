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

/// Constant-time multiplicative inverse in Montgomery form.
///
/// Returns `Some(self⁻¹ mod n)` when the value is coprime to the
/// modulus and the backend can compute the inverse. Bridged from
/// `subtle::CtOption` via `.into_option()` — same pattern as
/// `NonZero::new` — on backends whose native return is `CtOption`.
///
/// # Failure modes — non-interchangeable
///
/// `None` conflates two distinct cases; **callers must not treat them
/// as interchangeable "retry with fresh input"**:
///
/// 1. **Value not coprime to `n`** — retryable. Astronomically rare
///    when `self` was constructed from a fresh random against RSA
///    `n = p·q`, but real. Retry with a fresh random up to a small
///    constant number of times.
///
/// 2. **Backend precondition unmet** — **deterministic**. On the
///    modmath backend, `Field<T, Ct>::inv_safegcd_ct` requires the
///    carrier `T` to have one bit of headroom over the modulus (see
///    modmath's docs on the `2·modulus ≤ T::MAX` precondition). When
///    the modulus fills the carrier's full width (e.g. `U2048` for a
///    2048-bit RSA modulus at 32-bit limbs), every call returns
///    `None`. Retrying does not help. Pick `T` one bit wider than
///    the modulus (e.g. `U2080` for a 2048-bit modulus). The
///    `BoxedUint` backend has no fixed carrier and does not exhibit
///    this case.
///
/// A blinding loop built on this primitive should preflight the
/// carrier headroom for the modmath backend (compare modulus MSB
/// against carrier width) and bail with a permanent error before
/// entering the retry loop.
///
/// Consumed by `crate::algorithms::rsa::rsa_private_op_blinded` for
/// the sign-path blinding body. Plain code span rather than an
/// intra-doc link because the target is feature-gated and would
/// break `cargo doc --no-default-features`.
pub trait InvertCt<M: ModulusParams>: Sized {
    fn invert_ct(&self) -> Option<Self>;
}

#[cfg(feature = "alloc")]
impl InvertCt<BoxedMontyParams> for BoxedMontyForm {
    fn invert_ct(&self) -> Option<Self> {
        self.invert().into_option()
    }
}

/// Constant-time multiplication in Montgomery form.
///
/// The Montgomery form's native multiplication — already CT on both
/// backends we support (`BoxedMontyForm`'s `Mul` via crypto-bigint,
/// `ModMathForm<T, Ct>`'s `Field::mul` via modmath's CIOS-Ct). Bounded
/// on the sign-path blinding body, which does two Mont-form multiplies
/// per signature: `mont(c) * mont(r^e)` (blind) and
/// `mont(s') * mont(r⁻¹)` (unblind).
///
/// Both operands must share the same `ModulusParams` instance
/// (invariant: same modulus / same Montgomery R). We don't check that
/// at the type level; the impls take it as an unchecked precondition.
///
/// Consumed by `crate::algorithms::rsa::rsa_private_op_blinded` for
/// the two Mont-form multiplies per signature. Plain code span
/// rather than an intra-doc link because the target is feature-gated
/// and would break `cargo doc --no-default-features`.
pub trait MulCt<M: ModulusParams>: Sized {
    fn mul_ct(&self, rhs: &Self) -> Self;
}

#[cfg(feature = "alloc")]
impl MulCt<BoxedMontyParams> for BoxedMontyForm {
    fn mul_ct(&self, rhs: &Self) -> Self {
        self * rhs
    }
}

/// Sample a uniform random value in `[0, modulus)` from a CSPRNG.
///
/// Rejection-sampled: fills a buffer, checks against the modulus,
/// retries on `>= modulus`. Vartime in the number of retries (which
/// depends only on the modulus's top-bit density, not on the sampled
/// value itself — rejected candidates are discarded and don't reach
/// the caller). For RSA moduli where the top bit is set (typical for
/// keys generated by any real KDF), acceptance rate is ≥ 50% and the
/// bounded retry cap on the impls is effectively never hit.
///
/// Consumed by the RNG-taking sign path (follow-up PR) to sample the
/// blinding factor `r` that feeds
/// `crate::algorithms::rsa::rsa_private_op_blinded`.
#[allow(dead_code)]
pub trait TryRandomMod: Sized {
    fn try_random_mod<R>(rng: &mut R, modulus: &Self) -> Result<Self>
    where
        R: rand_core::TryCryptoRng + ?Sized;
}

#[cfg(feature = "alloc")]
impl TryRandomMod for BoxedUint {
    fn try_random_mod<R>(rng: &mut R, modulus: &Self) -> Result<Self>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let nz = CryptoNonZero::new(modulus.clone())
            .into_option()
            .ok_or(Error::InvalidModulus)?;
        <Self as crypto_bigint::RandomMod>::try_random_mod_vartime(rng, &nz).map_err(|_| Error::Rng)
    }
}

pub trait ModulusParams: Sized {
    type Modulus: UnsignedModularInt;
    type MontgomeryForm: IntoMontyForm<Self> + PowBoundedExp<Self>;
    fn modulus(&self) -> &Odd<Self::Modulus>;
    fn bits_precision(&self) -> u32;
}

pub(crate) mod sealed {
    /// Prevents external crates from implementing
    /// [`super::CtModulusParams`] on backends we haven't audited —
    /// see the security note on that trait.
    pub trait CtModulusParamsSealed {}
}

/// Marker trait for [`ModulusParams`] backends whose Montgomery
/// exponentiation itself is constant-time in the base value.
///
/// Bound the public-key encryption path on this so plaintext (which
/// **is** secret) can't be routed through a vartime `pow_bounded_exp`.
/// Signature verification stays unbounded — the "base" there is the
/// public signature, so vartime is fine.
///
/// The trait is sealed — only backends impl'd by this crate can opt
/// in. Downstream crates cannot claim the guarantee for their own
/// backends without inviting the exact side-channel this bound is
/// meant to keep out.
///
/// # Backends
///
/// - Under `feature = "alloc"`, `crypto_bigint::modular::BoxedMontyParams`
///   opts in. Its `BoxedMontyForm::pow_bounded_exp` is CT in the
///   base. **Caveat:** the pre-exponentiation conversion (see
///   `IntoMontyForm::from_value` for `BoxedMontyForm`) still uses a
///   vartime reduction (`BoxedUint::rem_vartime`) inherited from
///   upstream `RustCrypto/RSA`. Callers requiring rigorous CT
///   guarantees over the whole encrypt chain should use the no-alloc
///   modmath backend at the `Ct` personality (below). The alloc
///   impl is included primarily for API-surface compatibility with
///   upstream and to keep the default alloc encrypt path functional.
/// - Under `feature = "modmath"`, `ModMathParams<T, Ct>` opts in —
///   the no-alloc CT-personality substitution, honestly CT top to
///   bottom.
/// - `ModMathParams<T, Nct>` **deliberately does not** opt in;
///   `NctPublicKey`-derived encrypting keys fail the encrypt trait
///   bound at compile time.
pub trait CtModulusParams: ModulusParams + sealed::CtModulusParamsSealed {}

#[cfg(feature = "alloc")]
impl sealed::CtModulusParamsSealed for BoxedMontyParams {}
#[cfg(feature = "alloc")]
impl CtModulusParams for BoxedMontyParams {}

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
