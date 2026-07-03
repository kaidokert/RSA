//! Traits related to the key components

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crate::traits::{modular::ModulusParams, NonZero, UnsignedModularInt};

/// Marker trait gating the raw `(public_key, d)` constructor on
/// [`crate::key::GenericRsaPrivateKey`] (`from_public_and_d`). Backends
/// that impl this trait opt in to constructing private keys without
/// `primes` or CRT precompute — suitable for the heapless /
/// `wip-private-key` path where the caller already holds validated
/// `(n, e, d)` material from outside (e.g. PEM/PKCS#8 on disk,
/// HSM-derived).
///
/// **Intentionally NOT impl'd for [`BoxedUint`]** — alloc-side callers
/// must use `RsaPrivateKey::from_components` / `from_p_q` /
/// `from_primes`, which validate the key and populate `primes`
/// (recovering them via NIST SP 800-56B § C.2 when not provided).
/// Without that, empty `primes` would leak into CRT-aware APIs
/// (`precompute`, `crt_coefficient`, PKCS#1 encoding) as `primes[0]`
/// index panics.
#[cfg(any(feature = "private-key", feature = "wip-private-key"))]
pub trait RawPrivateKeyConstructible: UnsignedModularInt {}

// Heapless build: every `FixedWidthUnsignedInt + PartialOrd` matches
// the heapless `UnsignedModularInt` blanket in `traits/modular.rs` and
// gets the marker for free. `BoxedUint` isn't `Copy`, so it can never
// satisfy `FixedWidthUnsignedInt` — excluded structurally.
#[cfg(all(
    any(feature = "private-key", feature = "wip-private-key"),
    not(feature = "alloc")
))]
impl<T> RawPrivateKeyConstructible for T where
    T: crate::traits::modular::FixedWidthUnsignedInt + PartialOrd
{
}

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

/// Components of an RSA private key — generic over the integer /
/// Montgomery-parameter backend.
///
/// Mirrors [`PublicKeyParts`] in shape: generic over the integer
/// type `T`, no concrete dependency on `BoxedUint`/`BoxedMontyParams`.
/// The base surface is `d()`; the CRT accessors (`dp`/`dq`/`qinv`/
/// `p_params`/`q_params`) are gated on `feature = "private-key"` so
/// they only exist on the alloc path — heapless callers physically
/// can't reach them. Default impls return `None` so a generic key
/// without precomputed CRT values (e.g. [`GenericRsaPrivateKey`])
/// satisfies the trait with the minimum.
#[cfg(any(feature = "private-key", feature = "wip-private-key"))]
pub trait PrivateKeyParts<T>: PublicKeyParts<T>
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
