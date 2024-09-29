use core::hash::{Hash, Hasher};
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::traits::UnsignedModularInt;

use crate::errors::{Error, Result};
use crate::traits::{PaddingScheme, PrivateKeyParts, PublicKeyParts, SignatureScheme};
use crate::CrtValue;

/// Represents the public part of an RSA key.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RsaPublicKey<T>
where
    T: UnsignedModularInt,
{
    /// Modulus: product of prime numbers `p` and `q`
    n: T,
    /// Public exponent: power to which a plaintext message is raised in
    /// order to encrypt it.
    ///
    /// Typically 0x10001 (65537)
    e: T,
}

/// Represents a whole RSA key, public and private parts.
#[derive(Debug, Clone)]
pub struct RsaPrivateKey<T>
where
    T: UnsignedModularInt,
{
    /// Public components of the private key.
    pubkey_components: RsaPublicKey<T>,
    /// Private exponent
    pub(crate) d: T,
    /// Prime factors of N, contains >= 2 elements.
    pub(crate) primes: [T; 4],
    /// precomputed values to speed up private operations
    pub(crate) precomputed: Option<PrecomputedValues<T>>,
}

impl<T: UnsignedModularInt> Eq for RsaPrivateKey<T> {}
impl<T: UnsignedModularInt> PartialEq for RsaPrivateKey<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.pubkey_components == other.pubkey_components
            && self.d == other.d
            && self.primes == other.primes
    }
}

impl<T: UnsignedModularInt> AsRef<RsaPublicKey<T>> for RsaPrivateKey<T> {
    fn as_ref(&self) -> &RsaPublicKey<T> {
        &self.pubkey_components
    }
}

impl<T: UnsignedModularInt> Drop for RsaPrivateKey<T> {
    fn drop(&mut self) {
        self.d.zeroize();
        self.primes.zeroize();
        self.precomputed.zeroize();
    }
}

impl<T: UnsignedModularInt> ZeroizeOnDrop for RsaPrivateKey<T> {}

#[derive(Debug, Clone)]
pub(crate) struct PrecomputedValues<T: Zeroize + UnsignedModularInt> {
    /// D mod (P-1)
    pub(crate) dp: T,
    /// D mod (Q-1)
    pub(crate) dq: T,
    /// Q^-1 mod P
    pub(crate) qinv: T,

    /// CRTValues is used for the 3rd and subsequent primes. Due to a
    /// historical accident, the CRT for the first two primes is handled
    /// differently in PKCS#1 and interoperability is sufficiently
    /// important that we mirror this.
    pub(crate) crt_values: [CrtValue<T>; 3],
}

impl<T: Zeroize + UnsignedModularInt> Zeroize for PrecomputedValues<T> {
    fn zeroize(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        for val in self.crt_values.iter_mut() {
            val.zeroize();
        }
    }
}

impl<T: Zeroize + UnsignedModularInt> Drop for PrecomputedValues<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: UnsignedModularInt> PublicKeyParts<T> for RsaPublicKey<T> {
    fn n(&self) -> &T {
        &self.n
    }

    fn e(&self) -> &T {
        &self.e
    }
}

impl<T: UnsignedModularInt + Clone> RsaPublicKey<T> {
    /// Verify a signed message.
    ///
    /// `hashed` must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    ///
    /// If the message is valid `Ok(())` is returned, otherwise an `Err` indicating failure.
    pub fn verify<S: SignatureScheme<T>>(
        &self,
        scheme: S,
        hashed: &[u8],
        sig: &[u8],
    ) -> Result<()> {
        scheme.verify(self, hashed, sig)
    }
}

impl<T: UnsignedModularInt> RsaPublicKey<T> {
    /// Minimum value of the public exponent `e`.
    pub const MIN_PUB_EXPONENT: u64 = 2;

    /// Maximum value of the public exponent `e`.
    pub const MAX_PUB_EXPONENT: u64 = (1 << 33) - 1;

    /// Maximum size of the modulus `n` in bits.
    pub const MAX_SIZE: usize = 4096;

    /// Create a new public key from its components.
    ///
    /// This function accepts public keys with a modulus size up to 4096-bits,
    /// i.e. [`RsaPublicKey::MAX_SIZE`].
    pub fn new(n: T, e: T) -> Result<Self> {
        Self::new_with_max_size(n, e, Self::MAX_SIZE)
    }

    /// Create a new public key from its components.
    pub fn new_with_max_size(n: T, e: T, max_size: usize) -> Result<Self> {
        let k = Self { n, e };
        check_public_with_max_size(&k, max_size)?;
        Ok(k)
    }

    /// Create a new public key, bypassing checks around the modulus and public
    /// exponent size.
    ///
    /// This method is not recommended, and only intended for unusual use cases.
    /// Most applications should use [`RsaPublicKey::new`] or
    /// [`RsaPublicKey::new_with_max_size`] instead.
    pub fn new_unchecked(n: T, e: T) -> Self {
        Self { n, e }
    }
}

impl<T: UnsignedModularInt> PublicKeyParts<T> for RsaPrivateKey<T> {
    fn n(&self) -> &T {
        &self.pubkey_components.n
    }

    fn e(&self) -> &T {
        &self.pubkey_components.e
    }
    fn size(&self) -> usize {
        todo!("Not yet implemented size")
    }
}

impl<T: UnsignedModularInt> RsaPrivateKey<T> {
    /// Default exponent for RSA keys.
    const EXP: u64 = 65537;

    /// Constructs an RSA key pair from individual components:
    ///
    /// - `n`: RSA modulus
    /// - `e`: public exponent (i.e. encrypting exponent)
    /// - `d`: private exponent (i.e. decrypting exponent)
    /// - `primes`: prime factors of `n`: typically two primes `p` and `q`. More than two primes can
    ///   be provided for multiprime RSA, however this is generally not recommended. If no `primes`
    ///   are provided, a prime factor recovery algorithm will be employed to attempt to recover the
    ///   factors (as described in [NIST SP 800-56B Revision 2] Appendix C.2). This algorithm only
    ///   works if there are just two prime factors `p` and `q` (as opposed to multiprime), and `e`
    ///   is between 2^16 and 2^256.
    ///
    ///  [NIST SP 800-56B Revision 2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf
    pub fn from_components(n: T, e: T, d: T, mut primes: [T; 4]) -> Result<Self> {
        todo!("")
    }

    /// Constructs an RSA key pair from its two primes p and q.
    ///
    /// This will rebuild the private exponent and the modulus.
    ///
    /// Private exponent will be rebuilt using the method defined in
    /// [NIST 800-56B Section 6.2.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf#page=47).
    pub fn from_p_q(p: T, q: T, public_exponent: T) -> Result<Self> {
        if p == q {
            return Err(Error::InvalidPrime);
        }
        todo!()
    }

    /// Constructs an RSA key pair from its primes.
    ///
    /// This will rebuild the private exponent and the modulus.
    pub fn from_primes(primes: [T; 4], public_exponent: T) -> Result<Self> {
        if primes.len() < 2 {
            return Err(Error::NprimesTooSmall);
        }

        // Makes sure that primes is pairwise unequal.
        for (i, prime1) in primes.iter().enumerate() {
            for prime2 in primes.iter().take(i) {
                if prime1 == prime2 {
                    return Err(Error::InvalidPrime);
                }
            }
        }
        todo!()
    }

    /// Get the public key from the private key, cloning `n` and `e`.
    ///
    /// Generally this is not needed since `RsaPrivateKey` implements the `PublicKey` trait,
    /// but it can occasionally be useful to discard the private information entirely.
    pub fn to_public_key(&self) -> RsaPublicKey<T> {
        self.pubkey_components.clone()
    }

    /// Performs some calculations to speed up private key operations.
    pub fn precompute(&mut self) -> Result<()> {
        if self.precomputed.is_some() {
            return Ok(());
        }
        todo!()
    }

    /// Clears precomputed values by setting to None
    pub fn clear_precomputed(&mut self) {
        self.precomputed = None;
    }

    /// Compute CRT coefficient: `(1/q) mod p`.
    pub fn crt_coefficient(&self) -> Option<T> {
        todo!()
    }

    /// Performs basic sanity checks on the key.
    /// Returns `Ok(())` if everything is good, otherwise an appropriate error.
    pub fn validate(&self) -> Result<()> {
        check_public(self)?;

        // Check that Πprimes == n.
        let mut m = T::one();
        for prime in &self.primes {
            // Any primes ≤ 1 will cause divide-by-zero panics later.
            if *prime < T::one() {
                return Err(Error::InvalidPrime);
            }
            m = m * *prime;
        }
        if m != self.pubkey_components.n {
            return Err(Error::InvalidModulus);
        }

        // Check that de ≡ 1 mod p-1, for each prime.
        // This implies that e is coprime to each p-1 as e has a multiplicative
        // inverse. Therefore e is coprime to lcm(p-1,q-1,r-1,...) =
        // exponent(ℤ/nℤ). It also implies that a^de ≡ a mod p as a^(p-1) ≡ 1
        // mod p. Thus a^de ≡ a mod n for all a coprime to n, as required.
        let mut de = self.e().clone();
        de = de * self.d.clone();
        for prime in &self.primes {
            let congruence: T = *&de % (*prime - T::one());
            if !congruence.is_one() {
                return Err(Error::InvalidExponent);
            }
        }

        Ok(())
    }
}

impl<T: UnsignedModularInt> PrivateKeyParts<T> for RsaPrivateKey<T> {
    fn d(&self) -> &T {
        &self.d
    }

    fn primes(&self) -> &[T] {
        &self.primes
    }

    fn dp(&self) -> Option<&T> {
        self.precomputed.as_ref().map(|p| &p.dp)
    }

    fn dq(&self) -> Option<&T> {
        self.precomputed.as_ref().map(|p| &p.dq)
    }

    fn qinv(&self) -> Option<&T> {
        self.precomputed.as_ref().map(|p| &p.qinv)
    }

    fn crt_values(&self) -> Option<&[CrtValue<T>]> {
        /* for some reason the standard self.precomputed.as_ref().map() doesn't work */
        if let Some(p) = &self.precomputed {
            Some(p.crt_values.as_slice())
        } else {
            None
        }
    }
}

/// Check that the public key is well formed and has an exponent within acceptable bounds.
#[inline]
pub fn check_public<T>(public_key: &impl PublicKeyParts<T>) -> Result<()>
where
    T: UnsignedModularInt,
{
    check_public_with_max_size(public_key, RsaPublicKey::<T>::MAX_SIZE)
}

/// Check that the public key is well formed and has an exponent within acceptable bounds.
#[inline]
fn check_public_with_max_size<T>(public_key: &impl PublicKeyParts<T>, max_size: usize) -> Result<()>
where
    T: UnsignedModularInt,
{
    if public_key.n().bits() > max_size {
        return Err(Error::ModulusTooLarge);
    }

    let e = public_key
        .e()
        .to_u64()
        .ok_or(Error::PublicExponentTooLarge)?;

    if public_key.e() >= public_key.n() || public_key.n().is_even() {
        return Err(Error::InvalidModulus);
    }

    if public_key.e().is_even() {
        return Err(Error::InvalidExponent);
    }

    if e < RsaPublicKey::<T>::MIN_PUB_EXPONENT {
        return Err(Error::PublicExponentTooSmall);
    }

    if e > RsaPublicKey::<T>::MAX_PUB_EXPONENT {
        return Err(Error::PublicExponentTooLarge);
    }

    Ok(())
}
