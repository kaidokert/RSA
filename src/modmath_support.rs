//! Generic `modmath` backend adapters for fixed-width RSA public-key paths.

// TODO: document the public surface once the trait shape settles.
#![allow(missing_docs)]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::ops::{Rem, Shr, ShrAssign};

use modmath::{
    compute_n_prime_newton, compute_r2_mod_n, compute_r_mod_n, type_bit_width, CiosMontMul, Parity,
    WideMul,
};
use num_traits::ops::overflowing::OverflowingAdd;
use num_traits::ops::wrapping::{WrappingAdd, WrappingMul, WrappingSub};
use num_traits::{One, Zero};
use zeroize::Zeroize;

use crate::{
    algorithms::rsa::rsa_encrypt,
    errors::{Error, Result},
    key::GenericRsaPublicKey,
    traits::{
        modular::{
            IntegerResize, IntoMontyForm, ModulusParams, NonZero, Odd, Pow, PowBoundedExp,
            TryFromBeBytes, UnsignedModularInt,
        },
        FixedWidthUnsignedInt,
    },
};

pub trait ModMathInt:
    FixedWidthUnsignedInt
    + From<u8>
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
    + Rem<Output = Self>
    + Shr<usize, Output = Self>
    + ShrAssign<usize>
{
}

impl<T> ModMathInt for T where
    T: FixedWidthUnsignedInt
        + From<u8>
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
        + Rem<Output = Self>
        + Shr<usize, Output = Self>
        + ShrAssign<usize>
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
    T: ModMathInt,
{
    fn from(value: u8) -> Self {
        Self(<T as From<u8>>::from(value))
    }
}

#[cfg(feature = "alloc")]
impl<T> IntegerResize for ModMathValue<T>
where
    T: ModMathInt,
{
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
impl<T> UnsignedModularInt for ModMathValue<T>
where
    T: ModMathInt,
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

    fn rem_vartime(&self, modulus: &NonZero<Self>) -> Self {
        Self(self.0 % modulus.as_ref().0)
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
    T: ModMathInt,
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
pub struct ModMathParams<T: ModMathInt> {
    modulus: Odd<ModMathValue<T>>,
    // Montgomery constants for R = 2^W, where W = type_bit_width::<T>().
    // n_prime satisfies modulus * n_prime ≡ -1 (mod R).
    n_prime: T,
    // r_mod_n = R mod modulus = 2^W mod modulus.  Also serves as 1 in Montgomery form.
    r_mod_n: T,
    // r2_mod_n = R^2 mod modulus.  Used by wide_montgomery_mul to convert into Montgomery form.
    r2_mod_n: T,
}

impl<T: ModMathInt> ModMathParams<T> {
    /// Create modular arithmetic parameters for an odd, non-zero modulus.
    pub fn new(modulus: T) -> Result<Self> {
        let modulus_odd = Odd::new(wrap_value(modulus)).ok_or(Error::InvalidModulus)?;
        let w = type_bit_width::<T>();
        let n_prime = compute_n_prime_newton(modulus, w);
        let r_mod_n = compute_r_mod_n(modulus, w);
        let r2_mod_n = compute_r2_mod_n(r_mod_n, modulus, w);
        Ok(Self {
            modulus: modulus_odd,
            n_prime,
            r_mod_n,
            r2_mod_n,
        })
    }
}

/// Construct a public key backed by the `modmath` adapter from big-endian
/// modulus bytes and a public exponent.
pub fn public_key_from_be_bytes<T>(
    modulus: &[u8],
    exponent: u32,
) -> Result<GenericRsaPublicKey<ModMathValue<T>, ModMathParams<T>>>
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
    GenericRsaPublicKey::from_components(n, e, ModMathParams::new(unwrap_value(&n))?)
}

/// Apply the raw RSA public operation to a fixed-width block.
///
/// For signature use-cases this recovers the encoded message representative.
pub fn rsa_decrypt<T>(
    key: &GenericRsaPublicKey<ModMathValue<T>, ModMathParams<T>>,
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

/// A value held in Montgomery form modulo a `ModMathParams` modulus.
///
/// `integer_mont` stores `a * R mod N`, where `R = 2^W` and `W = type_bit_width::<T>()`.
#[derive(Clone, Debug)]
pub struct ModMathForm<T: ModMathInt> {
    integer_mont: ModMathValue<T>,
    params: ModMathParams<T>,
}

impl<T: ModMathInt> IntoMontyForm<ModMathParams<T>> for ModMathForm<T> {
    fn from_reduced(integer: ModMathValue<T>, params: &ModMathParams<T>) -> Self {
        // a_mont = a * R mod N, computed via CIOS as a * R^2 * R^-1 mod N.
        let a_mont = T::cios_mont_mul(
            unwrap_value_ref(&integer),
            &params.r2_mod_n,
            unwrap_value_ref(params.modulus.as_ref()),
            &params.n_prime,
        )
        .expect("CIOS Montgomery mul requires non-empty word array");
        Self {
            integer_mont: wrap_value(a_mont),
            params: params.clone(),
        }
    }
}

impl<T: ModMathInt> ModMathForm<T> {
    fn pow_loop(&self, exp_raw: T) -> T {
        let modulus = unwrap_value_ref(self.params.modulus.as_ref());
        let n_prime = &self.params.n_prime;
        let mut base_mont = unwrap_value(&self.integer_mont);
        // 1 in Montgomery form is R mod N.
        let mut result_mont = self.params.r_mod_n;
        let mut e = exp_raw;
        while !e.is_zero() {
            if e.is_odd() {
                result_mont = T::cios_mont_mul(&result_mont, &base_mont, modulus, n_prime)
                    .expect("CIOS Montgomery mul requires non-empty word array");
            }
            base_mont = T::cios_mont_mul(&base_mont, &base_mont, modulus, n_prime)
                .expect("CIOS Montgomery mul requires non-empty word array");
            e >>= 1;
        }
        result_mont
    }

    fn to_reduced(&self) -> T {
        // a_mont * 1 * R^-1 mod N = a (regular form).
        let one = <T as From<u8>>::from(1u8);
        T::cios_mont_mul(
            unwrap_value_ref(&self.integer_mont),
            &one,
            unwrap_value_ref(self.params.modulus.as_ref()),
            &self.params.n_prime,
        )
        .expect("CIOS Montgomery mul requires non-empty word array")
    }
}

impl<T: ModMathInt> Pow<ModMathParams<T>> for ModMathForm<T> {
    fn pow(&self, exp: &ModMathValue<T>) -> Self {
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

impl<T: ModMathInt> PowBoundedExp<ModMathParams<T>> for ModMathForm<T> {
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

impl<T: ModMathInt> ModulusParams for ModMathParams<T> {
    type Modulus = ModMathValue<T>;
    type MontgomeryForm = ModMathForm<T>;

    fn modulus(&self) -> &Odd<Self::Modulus> {
        &self.modulus
    }

    fn bits_precision(&self) -> u32 {
        self.modulus.bits_precision()
    }
}

#[cfg(test)]
#[cfg(all(feature = "alloc", feature = "private-key"))]
mod tests {
    use fixed_bigint::FixedUInt;
    use rand::rngs::ChaCha8Rng;
    use rand_core::SeedableRng;
    use sha1::Sha1;
    use signature::hazmat::PrehashVerifier;

    use super::{public_key_from_be_bytes, ModMathParams, ModMathValue};
    use crate::key::GenericRsaPublicKey;
    use crate::pkcs1v15::{GenericEncryptingKey, GenericSignature, GenericVerifyingKey};
    use crate::{traits::RandomizedEncryptor, BoxedUint, Pkcs1v15Encrypt, RsaPublicKey};

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
        let key = GenericRsaPublicKey::from_components(
            ModMathValue::from_inner(n),
            ModMathValue::from_inner(e),
            ModMathParams::new(n).unwrap(),
        )
        .unwrap();
        let verifying_key = GenericVerifyingKey::<Sha1, _, _>::new(key);
        let signature =
            GenericSignature::from(ModMathValue::from_inner(U512::from_be_bytes(&signature)));
        verifying_key.verify_prehash(&digest, &signature).unwrap();
    }

    #[test]
    fn encrypt_pkcs1v15_with_modmath_fixed_uint_matches_boxeduint() {
        type U512 = FixedUInt<u8, 64>;

        let modulus: [u8; 64] = [
            0x96, 0x9D, 0x03, 0xFF, 0xA9, 0x8D, 0x88, 0x8F, 0x3A, 0xA4, 0xF2, 0xFE, 0xD2, 0x32,
            0xE6, 0x1C, 0x4A, 0xCF, 0x06, 0x63, 0xA9, 0x2F, 0x99, 0x03, 0x4C, 0xF7, 0xB7, 0x24,
            0x5A, 0x1A, 0x1E, 0x5E, 0xAF, 0xA5, 0x65, 0xAF, 0xB9, 0x0B, 0xAB, 0x22, 0x85, 0x71,
            0x2F, 0xAA, 0x50, 0x39, 0x39, 0xA0, 0x65, 0xFB, 0x60, 0xDD, 0x08, 0x28, 0xA3, 0x84,
            0xF2, 0x6D, 0x8A, 0xFC, 0x28, 0x6D, 0xF6, 0xCF,
        ];
        let msg = b"hello world!";

        let modmath_key = public_key_from_be_bytes::<U512>(&modulus, 3).unwrap();
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
