//! Traits related to the key components

#[cfg(feature = "alloc")]
use crate::key::SecretPrime;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crate::traits::{modular::ModulusParams, NonZero, UnsignedModularInt};

/// Marker trait gating the raw `(public_key, d)` constructor
/// [`crate::key::GenericRsaPrivateKey::from_public_and_d`]. Backends opt
/// in to building private keys without `primes` or CRT precompute — the
/// heapless path, where the caller already holds validated `(n, e, d)`.
///
/// **Not impl'd for [`BoxedUint`]**: alloc callers must use the validated
/// `RsaPrivateKey::from_components` / `from_p_q` / `from_primes` paths, so
/// empty `primes` can't leak into CRT-aware APIs as a `primes[0]` panic.
pub trait RawPrivateKeyConstructible: UnsignedModularInt {}

// Heapless build: `FixedWidthUnsignedInt + PartialOrd` matches the
// `UnsignedModularInt` blanket and gets the marker for free. `BoxedUint`
// isn't `Copy`, so it can't satisfy `FixedWidthUnsignedInt`.
#[cfg(not(feature = "alloc"))]
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

    /// Returns `k`, the modulus length in octets from RFC8017: `ceil(modBits / 8)`.
    ///
    /// Ciphertexts and signatures have this length, including any leading zero octets.
    /// This may be smaller than the modulus's allocated storage width.
    fn size(&self) -> usize {
        (self.n().bits() as usize).div_ceil(8)
    }

    /// Returns the parameters for montgomery operations.
    fn n_params(&self) -> &Self::MontyParams;

    /// Returns the limb-aligned storage precision of `n` in bits.
    ///
    /// This can exceed the modulus bit length (`modBits` in RFC8017). Use this precision for
    /// integer arithmetic and decoding representatives, and [`Self::size`] for wire encodings.
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
/// The base surface is `d()`; the CRT accessors (`p`/`q`/`dp`/`dq`/
/// `qinv`) are `alloc`-gated and default to `None`, so a
/// key without CRT precompute satisfies the trait with just `d()`.
pub trait PrivateKeyParts<T>: PublicKeyParts<T>
where
    T: UnsignedModularInt,
{
    /// Returns the private exponent of the key.
    fn d(&self) -> &T;

    /// Returns the odd prime factors of the modulus. Returns `&[]` for
    /// keys that don't store factors.
    #[cfg(feature = "alloc")]
    fn primes(&self) -> &[crypto_bigint::Odd<crypto_bigint::BoxedUint>] {
        &[]
    }

    /// Returns prime `p` if precomputed.
    #[cfg(feature = "alloc")]
    fn p(&self) -> Option<&SecretPrime> {
        None
    }

    /// Returns prime `q` if precomputed.
    #[cfg(feature = "alloc")]
    fn q(&self) -> Option<&SecretPrime> {
        None
    }

    /// Returns the precomputed `dp = d mod (p - 1)` value, if available.
    /// `None` for keys that didn't precompute CRT.
    #[cfg(feature = "alloc")]
    fn dp(&self) -> Option<&T> {
        None
    }

    /// Returns the precomputed `dq = d mod (q - 1)` value, if available.
    #[cfg(feature = "alloc")]
    fn dq(&self) -> Option<&T> {
        None
    }

    /// Returns the precomputed `qinv = q^-1 mod p` value, if available.
    #[cfg(feature = "alloc")]
    fn qinv(&self) -> Option<&<Self::MontyParams as ModulusParams>::MontgomeryForm> {
        None
    }
}
