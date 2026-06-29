//! Traits related to the key components

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "private-key")]
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint,
};
use zeroize::Zeroize;

use crate::traits::{modular::ModulusParams, NonZero, UnsignedModularInt};

/// Components of an RSA public key.
pub trait PublicKeyParts<T: UnsignedModularInt> {
    /// Montgomery parameter type matching this modulus type.
    type MontyParams: ModulusParams<Modulus = T>;

    /// Returns the modulus of the key.
    fn n(&self) -> &NonZero<T>;

    /// Returns the public exponent of the key.
    fn e(&self) -> &T;

    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    fn size(&self) -> usize {
        (self.n().bits() as usize).div_ceil(8)
    }

    /// Returns the parameters for montgomery operations.
    fn n_params(&self) -> &Self::MontyParams;

    /// Returns precision (in bits) of `n`.
    fn n_bits_precision(&self) -> u32 {
        self.n().bits_precision()
    }

    /// Returns the big endian serialization of the modulus of the key
    #[cfg(feature = "alloc")]
    fn n_bytes(&self) -> Box<[u8]> {
        self.n().to_be_bytes_trimmed_vartime()
    }

    /// Returns the big endian serialization of the public exponent of the key
    #[cfg(feature = "alloc")]
    fn e_bytes(&self) -> Box<[u8]> {
        self.e().to_be_bytes_trimmed_vartime()
    }
}

/// Generic components of an RSA private key — minimal trait for the
/// heapless / wip-private-key port.
///
/// Mirrors [`PublicKeyParts`] in shape: generic over the integer
/// type `T`, no concrete dependency on `BoxedUint`/`BoxedMontyParams`.
/// The base surface is `d()`; the CRT accessors (`dp`/`dq`/`qinv`/
/// `p_params`/`q_params`) are gated on `feature = "private-key"` so
/// they only exist on the alloc path — heapless callers physically
/// can't reach them. Default impls return `None` so a generic key
/// without precomputed CRT values (e.g. [`GenericRsaPrivateKey`])
/// satisfies the trait with the minimum.
///
/// The legacy [`PrivateKeyParts`] (alloc-bound, `BoxedUint`-concrete)
/// is bridged to this trait via a blanket impl, so any existing
/// `K: PrivateKeyParts` value also satisfies
/// `GenericPrivateKeyParts<BoxedUint>` — with the bridge forwarding
/// the CRT accessors when present.
#[cfg(any(feature = "private-key", feature = "wip-private-key"))]
pub trait GenericPrivateKeyParts<T>: PublicKeyParts<T>
where
    T: UnsignedModularInt,
{
    /// Returns the private exponent of the key.
    fn d(&self) -> &T;

    /// Returns the prime factors of the modulus. Returns `&[]` for keys
    /// that don't store factors (the heapless default).
    #[cfg(feature = "private-key")]
    fn primes(&self) -> &[T] {
        &[]
    }

    /// Returns the precomputed `dp = d mod (p - 1)` value, if available.
    /// `None` for keys that didn't precompute CRT (the heapless default).
    #[cfg(feature = "private-key")]
    fn dp(&self) -> Option<&T> {
        None
    }

    /// Returns the precomputed `dq = d mod (q - 1)` value, if available.
    #[cfg(feature = "private-key")]
    fn dq(&self) -> Option<&T> {
        None
    }

    /// Returns the precomputed `qinv = q^-1 mod p` value, if available.
    #[cfg(feature = "private-key")]
    fn qinv(&self) -> Option<&<Self::MontyParams as ModulusParams>::MontgomeryForm> {
        None
    }

    /// Returns the Montgomery parameters for `p`, if available.
    #[cfg(feature = "private-key")]
    fn p_params(&self) -> Option<&Self::MontyParams> {
        None
    }

    /// Returns the Montgomery parameters for `q`, if available.
    #[cfg(feature = "private-key")]
    fn q_params(&self) -> Option<&Self::MontyParams> {
        None
    }
}

/// Bridge: every legacy [`PrivateKeyParts`] impl also satisfies the
/// generic trait at the concrete `BoxedUint` substitution. Lets
/// existing alloc-side consumers (and the upstream
/// `algorithms::rsa::rsa_decrypt[_and_check]` path) be re-bound on
/// `GenericPrivateKeyParts` incrementally without breaking compilation.
/// Forwards the CRT accessors so the alloc-side CRT branch can run
/// purely against the generic trait surface.
#[cfg(feature = "private-key")]
impl<K> GenericPrivateKeyParts<BoxedUint> for K
where
    K: PrivateKeyParts + PublicKeyParts<BoxedUint, MontyParams = BoxedMontyParams>,
{
    fn d(&self) -> &BoxedUint {
        PrivateKeyParts::d(self)
    }

    fn primes(&self) -> &[BoxedUint] {
        PrivateKeyParts::primes(self)
    }

    fn dp(&self) -> Option<&BoxedUint> {
        PrivateKeyParts::dp(self)
    }

    fn dq(&self) -> Option<&BoxedUint> {
        PrivateKeyParts::dq(self)
    }

    fn qinv(&self) -> Option<&BoxedMontyForm> {
        PrivateKeyParts::qinv(self)
    }

    fn p_params(&self) -> Option<&BoxedMontyParams> {
        PrivateKeyParts::p_params(self)
    }

    fn q_params(&self) -> Option<&BoxedMontyParams> {
        PrivateKeyParts::q_params(self)
    }
}

/// Components of an RSA private key.
#[cfg(feature = "private-key")]
pub trait PrivateKeyParts: PublicKeyParts<BoxedUint> {
    /// Returns the private exponent of the key.
    fn d(&self) -> &BoxedUint;

    /// Returns the prime factors.
    fn primes(&self) -> &[BoxedUint];

    /// Returns the precomputed dp value, D mod (P-1)
    fn dp(&self) -> Option<&BoxedUint>;

    /// Returns the precomputed dq value, D mod (Q-1)
    fn dq(&self) -> Option<&BoxedUint>;

    /// Returns the precomputed qinv value, Q^-1 mod P
    fn qinv(&self) -> Option<&BoxedMontyForm>;

    /// Returns an iterator over the CRT Values
    fn crt_values(&self) -> Option<&[CrtValue]>;

    /// Returns the params for `p` if precomputed.
    fn p_params(&self) -> Option<&BoxedMontyParams>;

    /// Returns the params for `q` if precomputed.
    fn q_params(&self) -> Option<&BoxedMontyParams>;
}

/// Contains the precomputed Chinese remainder theorem values.
#[cfg(feature = "private-key")]
#[derive(Debug, Clone)]
pub struct CrtValue {
    /// D mod (prime - 1)
    pub(crate) exp: BoxedUint,
    /// R·Coeff ≡ 1 mod Prime.
    pub(crate) coeff: BoxedUint,
    /// product of primes prior to this (inc p and q)
    pub(crate) r: BoxedUint,
}

#[cfg(feature = "private-key")]
impl Zeroize for CrtValue {
    fn zeroize(&mut self) {
        self.exp.zeroize();
        self.coeff.zeroize();
        self.r.zeroize();
    }
}

#[cfg(feature = "private-key")]
impl Drop for CrtValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}
