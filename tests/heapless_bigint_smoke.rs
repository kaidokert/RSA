//! EXPERIMENT (bigint-heapless-runtime-len): the runtime-length carrier
//! against this crate's actual sign/verify surface.
//!
//! `fixed_bigint::HeaplessBigInt` is the fixed-capacity / runtime-length
//! bignum this experiment adopts. With the `FixedWidthUnsignedInt`
//! blanket rebound onto the vocabulary pair (`BitsPrecision` = the
//! constructed operating width, `BitWidth` = the value-defined
//! bit-length), the carrier reaches the whole modmath backend. Host-only.
//!
//! Width semantics through this trait surface: the `ToBytes`/`FromBytes`
//! holder is capacity-width by design, so values built via
//! `try_from_be_bytes_vartime` operate at `CAP` — exactly the RSA
//! deployment shape (a modulus constructed at `len == CAP`). Sub-capacity
//! runtime widths come from the carrier's inherent constructors and the
//! future runtime-len modmath kernels, not from this byte path.

use const_num_traits::{BitWidth, BitsPrecision, Ct, Nct};
use fixed_bigint::HeaplessBigInt;

/// 2048-bit capacity carrier (`u32` limbs × 64) — the deployment shape
/// the experiment targets.
type H = HeaplessBigInt<u32, 64>;
type HCt = HeaplessBigInt<u32, 64, Ct>;

// Real 2048-bit RSA keypair shared with the CT-verification harness.
include!("../ct-verify/test_keys.rs");

#[test]
fn be_bytes_roundtrip_and_shape() {
    // Two BE bytes → one u32 limb, width 32, value 0x0102 (9 bits).
    let v = H::from_be_bytes(&[0x01, 0x02]);
    assert_eq!(v.len(), 1);
    assert_eq!(v.capacity(), 64);
    assert_eq!(BitsPrecision::bits_precision(v), 32);
    assert_eq!(BitWidth::bit_width(v), 9);

    let mut buf = [0u8; 4];
    let out = v.to_be_bytes(&mut buf);
    assert_eq!(out, &[0x00, 0x00, 0x01, 0x02]);
}

#[test]
fn width_tracks_construction_not_capacity() {
    // A 256-byte (2048-bit) input fills all 64 limbs...
    let full = H::from_be_bytes(&[0xFF; 256]);
    assert_eq!(full.len(), 64);
    assert_eq!(BitsPrecision::bits_precision(full), 2048);
    assert_eq!(BitWidth::bit_width(full), 2048);

    // ...while a 64-byte (512-bit) input in the SAME carrier type is a
    // 512-bit-wide number — width is the constructed length, capacity
    // never leaks into either quantity.
    let small = H::from_be_bytes(&[0xFF; 64]);
    assert_eq!(small.len(), 16);
    assert_eq!(BitsPrecision::bits_precision(small), 512);
    assert_eq!(BitWidth::bit_width(small), 512);

    // Zero value, non-zero width: bit-length is value-defined (0),
    // width is shape-defined (64).
    let zero = H::new_zero_with_len(2);
    assert_eq!(BitsPrecision::bits_precision(zero), 64);
    assert_eq!(BitWidth::bit_width(zero), 0);
}

#[test]
fn arithmetic_smoke() {
    let a = H::from_be_bytes(&[0x00, 0x01, 0x00, 0x00]); // 65536
    let b = H::from_be_bytes(&[0x00, 0x00, 0xFF, 0xFF]); // 65535

    // Addition widens the result's public shape by one carry limb
    // (len 1 + len 1 → len 2) regardless of value — shape arithmetic
    // stays value-independent.
    let sum = a + b;
    assert_eq!(sum.len(), 2);
    let mut buf = [0u8; 8];
    assert_eq!(
        sum.to_be_bytes(&mut buf),
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF]
    );
}

/// Deterministic infallible RNG for the salt/blinding draw — the
/// stream only needs to be stable, not cryptographic, for a smoke test.
struct FixedRng(u64);
impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            for (d, s) in chunk.iter_mut().zip(bytes.iter()) {
                *d = *s;
            }
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for FixedRng {}

/// The prize: a whole 2048-bit blinded PKCS#1 v1.5 sign with the
/// runtime-length carrier at full capacity. The sign path runs
/// verify-after-sign internally (`rsa_private_op_and_check_blinded`
/// recomputes with the public exponent and compares), so a successful
/// sign also proves the verify math on this carrier.
///
/// Everything COMPILES; the run is ignored on one known upstream bug
/// (the unblinded path fails identically, so it is the modular math,
/// not the blinding): modmath 0.5 sizes Montgomery R via
/// `type_bit_width = size_of*8`, which reads HeaplessBigInt's STRUCT
/// size (limbs + len field + padding) — a phantom extra limb, so R² is
/// precomputed for R = 2^2080 while the 64-limb CIOS defines R =
/// 2^2048. WIDTH_AND_CT_MODEL marks type_bit_width "delete" (width
/// must come from the modulus's own public shape), but as of
/// v0.6.0-alpha.cios.2 no modmath tag carries that retirement yet —
/// new_odd/new_odd_ct/exp all still size from the struct.
/// fixed-bigint's WideMul len-split (fixed in 0.6.0-alpha.16) was
/// never RSA's blocker: montgomery operands here are full-width, so
/// the operand-len and CAP splits coincided.
///
/// Un-ignore when a modmath tag replaces type_bit_width with
/// modulus-shape-derived width and this branch adopts it.
#[test]
#[ignore = "blocked upstream: modmath type_bit_width sizes R off the carrier STRUCT (phantom limb for runtime-len); no tag carries the WIDTH_AND_CT_MODEL retirement yet"]
fn pkcs1v15_blinded_sign_2048() {
    use rsa::modmath_support::public_key_ct_from_be_bytes;
    use rsa::pkcs1v15::GenericSigningKey;
    use rsa::traits::FixedWidthUnsignedInt;
    use rsa::GenericRsaPrivateKey;
    use sha2::Sha256;

    let pubkey = public_key_ct_from_be_bytes::<HCt>(&N_2048, 65537).unwrap();
    // On the alloc build the modmath carrier is wrapped in the
    // `ModMathValue` newtype (on no-alloc it is a transparent alias).
    let d = rsa::modmath_support::ModMathValue(HCt::try_from_be_bytes_vartime(&D_2048).unwrap());
    let signing_key =
        GenericSigningKey::<Sha256, _, _>::new(GenericRsaPrivateKey::from_public_and_d(pubkey, d));

    let mut rng = FixedRng(0);
    let prehash = [0x42u8; 32];
    let mut em = [0u8; 256];
    let mut sig = [0u8; 256];
    signing_key
        .try_sign_prehash_with_rng_into(&mut rng, &prehash, &mut em, &mut sig)
        .expect("blinded sign with HeaplessBigInt carrier");
    assert_ne!(sig, [0u8; 256]);
}

// ── Carrier-trait status, pinned ────────────────────────────────────
mod carrier_traits {
    use super::*;
    use rsa::modmath_support::{ModMathIntCt, ModMathValue};
    use rsa::traits::{FixedWidthUnsignedInt, UnsignedModularInt};
    use static_assertions::assert_impl_all;

    // The vocabulary rebind reaches the carrier: byte/width surface and
    // the whole Ct bound bundle resolve for every personality's
    // byte/width part, and for Ct on the CIOS-Ct side.
    assert_impl_all!(H: FixedWidthUnsignedInt);
    assert_impl_all!(HCt: FixedWidthUnsignedInt, ModMathIntCt);
    assert_impl_all!(HeaplessBigInt<u32, 64, Nct>: FixedWidthUnsignedInt);

    // On the alloc build (this test's config) the carrier reaches
    // `UnsignedModularInt` through the `ModMathValue` newtype, same as
    // every other modmath carrier.
    assert_impl_all!(ModMathValue<HCt>: UnsignedModularInt);
}
