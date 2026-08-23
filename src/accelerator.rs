//! Operation-level RSA acceleration.
//!
//! This module keeps EMSA encoding and verification in this crate while a
//! peripheral performs only the RSA primitive. Two adapters cover distinct
//! key models:
//!
//! - [`ModularPublicKey`] and [`ModularPrivateKey`] use exportable big-endian
//!   `(n, e)` / `(n, d, e)` components through `modmath` operation traits.
//! - Implement [`RsaPrivateOperation`] directly when the private key is an
//!   opaque hardware handle and must never be exported.

use crate::{Error, Result};
use ctutils::CtEq;
use digest::{Digest, FixedOutputReset};
use modmath::accelerator::{ModularExponentiate, SecretModularExponentiate};
use zeroize::Zeroize;

/// A complete RSA public operation using a public key owned by the backend.
pub trait RsaPublicOperation {
    /// Backend-specific failure.
    type Error;

    /// Significant bit length of the RSA modulus.
    fn modulus_bits(&self) -> usize;

    /// Compute `output = input^e mod n` using equal-width big-endian buffers.
    fn public_operation(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> core::result::Result<(), Self::Error>;
}

/// A complete RSA private operation using a key owned by the backend.
pub trait RsaPrivateOperation {
    /// Backend-specific failure.
    type Error;

    /// Significant bit length of the RSA modulus.
    fn modulus_bits(&self) -> usize;

    /// Compute the private RSA primitive using equal-width big-endian buffers.
    fn private_operation(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> core::result::Result<(), Self::Error>;
}

/// Marker for private operations suitable for processing secret keys.
///
/// # Safety
///
/// The implementation must protect the private exponent or opaque key under
/// its documented side-channel model and must perform a public-operation fault
/// check before returning output. Hardware that provides internal blinding may
/// satisfy the first requirement without exporting its blinding state.
pub unsafe trait HardenedRsaPrivateOperation: RsaPrivateOperation {}

/// Error from an exportable-component private-operation adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateOperationError<E> {
    /// The modular accelerator failed.
    Backend(E),
    /// Public recomputation did not recover the operation input.
    FaultDetected,
    /// An input, output, or scratch buffer has the wrong size.
    OutputSize,
}

/// Public-key adapter over a `modmath` modular exponentiator.
pub struct ModularPublicKey<'key, A> {
    accelerator: A,
    modulus: &'key [u8],
    exponent: &'key [u8],
    modulus_bits: usize,
}

impl<'key, A> ModularPublicKey<'key, A> {
    /// Construct an adapter over borrowed, big-endian public components.
    pub fn new(
        accelerator: A,
        modulus: &'key [u8],
        exponent: &'key [u8],
        modulus_bits: usize,
    ) -> Self {
        Self {
            accelerator,
            modulus,
            exponent,
            modulus_bits,
        }
    }

    /// Borrow the underlying accelerator, for lifecycle or diagnostics.
    pub fn accelerator_mut(&mut self) -> &mut A {
        &mut self.accelerator
    }
}

impl<A: ModularExponentiate> RsaPublicOperation for ModularPublicKey<'_, A> {
    type Error = A::Error;

    fn modulus_bits(&self) -> usize {
        self.modulus_bits
    }

    fn public_operation(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        self.accelerator
            .modular_exponentiate(input, self.exponent, self.modulus, output)
    }
}

/// Exportable-component private-key adapter over a secret-safe modular
/// exponentiator. Every operation is checked with the public exponent.
pub struct ModularPrivateKey<'key, 'scratch, A> {
    accelerator: A,
    modulus: &'key [u8],
    private_exponent: &'key [u8],
    public_exponent: &'key [u8],
    modulus_bits: usize,
    check_scratch: &'scratch mut [u8],
}

impl<'key, 'scratch, A> ModularPrivateKey<'key, 'scratch, A> {
    /// Construct an adapter over borrowed, big-endian private components.
    ///
    /// `check_scratch` must be at least the modulus byte length. It holds only
    /// the public verify-after-operation result and is wiped after use.
    pub fn new(
        accelerator: A,
        modulus: &'key [u8],
        private_exponent: &'key [u8],
        public_exponent: &'key [u8],
        modulus_bits: usize,
        check_scratch: &'scratch mut [u8],
    ) -> Self {
        Self {
            accelerator,
            modulus,
            private_exponent,
            public_exponent,
            modulus_bits,
            check_scratch,
        }
    }

    /// Borrow the underlying accelerator, for lifecycle or diagnostics.
    pub fn accelerator_mut(&mut self) -> &mut A {
        &mut self.accelerator
    }
}

impl<A: SecretModularExponentiate> RsaPrivateOperation for ModularPrivateKey<'_, '_, A> {
    type Error = PrivateOperationError<A::Error>;

    fn modulus_bits(&self) -> usize {
        self.modulus_bits
    }

    fn private_operation(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        if input.len() != self.modulus.len() || output.len() != self.modulus.len() {
            return Err(PrivateOperationError::OutputSize);
        }
        self.accelerator
            .modular_exponentiate(input, self.private_exponent, self.modulus, output)
            .map_err(PrivateOperationError::Backend)?;

        let checked = self
            .check_scratch
            .get_mut(..self.modulus.len())
            .ok_or(PrivateOperationError::OutputSize)?;
        self.accelerator
            .modular_exponentiate(output, self.public_exponent, self.modulus, checked)
            .map_err(PrivateOperationError::Backend)?;
        if !checked.ct_eq(input).to_bool() {
            checked.zeroize();
            output.zeroize();
            return Err(PrivateOperationError::FaultDetected);
        }
        checked.zeroize();
        Ok(())
    }
}

// Safety follows from the `SecretModularExponentiate` contract plus the
// verify-after-private-operation check above.
unsafe impl<A: SecretModularExponentiate> HardenedRsaPrivateOperation
    for ModularPrivateKey<'_, '_, A>
{
}

fn modulus_len(bits: usize) -> Result<usize> {
    if bits < 2 || bits > 8192 {
        return Err(Error::InvalidModulus);
    }
    Ok(bits.div_ceil(8))
}

/// PKCS#1 v1.5-sign a prehash through an opaque or accelerated private key.
pub fn pkcs1v15_sign_prehash<'sig, K: HardenedRsaPrivateOperation>(
    key: &mut K,
    digest_info_prefix: &[u8],
    prehash: &[u8],
    em_storage: &mut [u8],
    sig_storage: &'sig mut [u8],
) -> Result<&'sig [u8]> {
    let k = modulus_len(key.modulus_bits())?;
    let em = crate::algorithms::pkcs1v15::pkcs1v15_sign_pad_into(
        digest_info_prefix,
        prehash,
        k,
        em_storage,
    )?;
    let signature = sig_storage
        .get_mut(..k)
        .ok_or(Error::OutputBufferTooSmall)?;
    if key.private_operation(em, signature).is_err() {
        signature.zeroize();
        return Err(Error::Internal);
    }
    Ok(signature)
}

/// Verify a PKCS#1 v1.5 prehash through an accelerated public key.
pub fn pkcs1v15_verify_prehash<K: RsaPublicOperation>(
    key: &mut K,
    digest_info_prefix: &[u8],
    prehash: &[u8],
    signature: &[u8],
    em_storage: &mut [u8],
) -> Result<()> {
    let k = modulus_len(key.modulus_bits())?;
    if signature.len() != k {
        return Err(Error::Verification);
    }
    let em = em_storage.get_mut(..k).ok_or(Error::OutputBufferTooSmall)?;
    key.public_operation(signature, em)
        .map_err(|_| Error::Verification)?;
    crate::algorithms::pkcs1v15::pkcs1v15_sign_unpad(digest_info_prefix, prehash, em, k)
}

/// PSS-sign a prehash and caller-generated salt through an accelerated key.
pub fn pss_sign_prehash<'sig, K, D>(
    key: &mut K,
    prehash: &[u8],
    salt: &[u8],
    hash: &mut D,
    em_storage: &mut [u8],
    sig_storage: &'sig mut [u8],
) -> Result<&'sig [u8]>
where
    K: HardenedRsaPrivateOperation,
    D: Digest + FixedOutputReset,
{
    let bits = key.modulus_bits();
    let k = modulus_len(bits)?;
    let em =
        crate::algorithms::pss::emsa_pss_encode_into(prehash, bits - 1, salt, hash, em_storage)?;
    let signature = sig_storage
        .get_mut(..k)
        .ok_or(Error::OutputBufferTooSmall)?;
    // EMSA-PSS can be one byte shorter than the modulus. Left-pad before the
    // primitive, as RFC 8017's OS2IP conversion would.
    signature.zeroize();
    let offset = k.checked_sub(em.len()).ok_or(Error::Internal)?;
    signature[offset..].copy_from_slice(em);
    if key
        .private_operation(
            signature,
            em_storage.get_mut(..k).ok_or(Error::OutputBufferTooSmall)?,
        )
        .is_err()
    {
        signature.zeroize();
        return Err(Error::Internal);
    }
    signature.copy_from_slice(&em_storage[..k]);
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentityKey;

    impl RsaPrivateOperation for IdentityKey {
        type Error = ();

        fn modulus_bits(&self) -> usize {
            1024
        }

        fn private_operation(
            &mut self,
            input: &[u8],
            output: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            output.copy_from_slice(input);
            Ok(())
        }
    }

    unsafe impl HardenedRsaPrivateOperation for IdentityKey {}

    impl RsaPublicOperation for IdentityKey {
        type Error = ();

        fn modulus_bits(&self) -> usize {
            1024
        }

        fn public_operation(
            &mut self,
            input: &[u8],
            output: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            output.copy_from_slice(input);
            Ok(())
        }
    }

    #[test]
    fn pkcs1_encoding_stays_around_the_private_operation() {
        let mut em = [0u8; 128];
        let mut signature = [0u8; 128];
        let signature = pkcs1v15_sign_prehash(
            &mut IdentityKey,
            &[0x30, 0x01],
            &[0xa5; 32],
            &mut em,
            &mut signature,
        )
        .unwrap();
        assert_eq!(&signature[..2], &[0, 1]);
        assert_eq!(&signature[96..], &[0xa5; 32]);
        pkcs1v15_verify_prehash(
            &mut IdentityKey,
            &[0x30, 0x01],
            &[0xa5; 32],
            signature,
            &mut em,
        )
        .unwrap();
    }

    #[test]
    fn backend_failure_wipes_signature_output() {
        struct Failed;
        impl RsaPrivateOperation for Failed {
            type Error = ();
            fn modulus_bits(&self) -> usize {
                1024
            }
            fn private_operation(
                &mut self,
                _: &[u8],
                out: &mut [u8],
            ) -> core::result::Result<(), ()> {
                out.fill(0x5a);
                Err(())
            }
        }
        unsafe impl HardenedRsaPrivateOperation for Failed {}

        let mut em = [0u8; 128];
        let mut signature = [0xa5u8; 128];
        assert_eq!(
            pkcs1v15_sign_prehash(&mut Failed, &[], &[1], &mut em, &mut signature),
            Err(Error::Internal)
        );
        assert_eq!(signature, [0; 128]);
    }

    #[test]
    fn pss_encoding_stays_around_the_private_operation() {
        let mut em = [0u8; 128];
        let mut signature = [0u8; 128];
        let signature = pss_sign_prehash::<_, sha2::Sha256>(
            &mut IdentityKey,
            &[0x42; 32],
            &[0x24; 32],
            &mut sha2::Sha256::new(),
            &mut em,
            &mut signature,
        )
        .unwrap();
        assert_eq!(signature.len(), 128);
        assert_eq!(signature[127], 0xbc);
        assert_eq!(signature[0] & 0x80, 0);
    }

    struct U16ModExp;

    impl ModularExponentiate for U16ModExp {
        type Error = ();

        fn modular_exponentiate(
            &mut self,
            base_be: &[u8],
            exponent_be: &[u8],
            modulus_be: &[u8],
            out: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            let decode = |bytes: &[u8]| {
                bytes
                    .iter()
                    .fold(0u32, |value, byte| (value << 8) | u32::from(*byte))
            };
            let modulus = decode(modulus_be);
            let mut base = decode(base_be) % modulus;
            let mut exponent = decode(exponent_be);
            let mut value = 1u32;
            while exponent != 0 {
                if exponent & 1 != 0 {
                    value = value * base % modulus;
                }
                base = base * base % modulus;
                exponent >>= 1;
            }
            out.copy_from_slice(&(value as u16).to_be_bytes());
            Ok(())
        }
    }

    unsafe impl SecretModularExponentiate for U16ModExp {}

    #[test]
    fn exportable_private_adapter_checks_the_public_round_trip() {
        // Textbook toy key: n=61*53=3233, e=17, d=2753.
        let mut check = [0u8; 2];
        let mut key = ModularPrivateKey::new(
            U16ModExp,
            &[0x0c, 0xa1],
            &[0x0a, 0xc1],
            &[0x11],
            12,
            &mut check,
        );
        let mut output = [0u8; 2];
        key.private_operation(&[0, 65], &mut output).unwrap();
        assert_eq!(output, [0x02, 0x4c]);
        assert_eq!(check, [0; 2]);
    }
}
