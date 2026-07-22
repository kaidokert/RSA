//! Linker-DCE audit for the heapless sign path.
//!
//! The `#[no_mangle] pub extern "C"` symbol exercises the whole
//! heapless PKCS#1 v1.5 sign the way a deployed consumer would: fallible
//! key construction handled with `if let Ok` (a `match`, never a
//! panicking `unwrap`), and the sign `Result` observed through
//! `black_box` rather than extracted. After cross-building with the
//! workspace release profile, krabi-caliper asserts the archive contains
//! no `core::panicking` machinery — for a signer a reachable panic is
//! both a DoS edge and a timing oracle (the panic-formatting path's cost
//! depends on the values being formatted).
//!
//! The *prehash* sign variant is used so the digest compression (public,
//! upstream `sha2`) stays out of the archive; the audit is scoped to
//! this crate's composition — PKCS#1 v1.5 padding, the blinded private
//! op, verify-after-sign, and serialization.

// no_std + the local #[panic_handler] only under the `panic-handler`
// feature (the cross-built audit shape, enabled by krabi-caliper). Host-side
// workspace builds (clippy) link std, which supplies its own.
#![cfg_attr(feature = "panic-handler", no_std)]

#[cfg(feature = "neg-controls")]
mod neg_controls;

use const_num_traits::Ct;
use core::hint::black_box;
use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_ct_from_be_bytes;
use rsa::pkcs1v15::GenericSigningKey;
use rsa::traits::FixedWidthUnsignedInt;
use rsa::GenericRsaPrivateKey;
use sha2::Sha256;

type Carrier = FixedUInt<u8, 64, Ct>;
/// 2048-bit (`u32` limbs) — the deployment width gets its own audit
/// fixture for the same reason it gets its own taint fixture: the
/// gates verify instantiations, not generic code. Limb width matters:
/// the fixed-bigint 0.5.0 `holder_be` panic was invisible at `u8`
/// limbs (1-byte copies fold), real at `u32`.
type CarrierW = FixedUInt<u32, 64, Ct>;
/// 2048-bit, `u8` limbs — the AVR-class flavor at deployment width.
type CarrierW8 = FixedUInt<u8, 256, Ct>;
/// 2048-bit, `u64` limbs — the 64-bit-host flavor (double-word `u128`
/// intermediates).
type CarrierW64 = FixedUInt<u64, 32, Ct>;

// Real RSA keypairs (`e = 65537`) shared with `ct-fixtures` via a
// textual include — see the fragment's module docs.
include!("../../../tests/fixtures/test_keys.rs");

include!("../../fixture_rng.rs");

/// Whole heapless PKCS#1 v1.5 blinded sign, panic-audited: no `unwrap`
/// on the fallible setup, sign `Result` observed not extracted.
/// # Safety
/// `out_ptr` must be a valid pointer to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn panic_audit__pkcs1v15_blinded_sign__fb8__N64(out_ptr: *mut u8) {
    let d_bytes = black_box(D_512);
    let prehash = black_box([0u8; 32]); // SHA-256 output width.

    let ok = if let Ok(pubkey) = public_key_ct_from_be_bytes::<Carrier>(&N_512, 65537) {
        if let Ok(d) = Carrier::try_from_be_bytes_vartime(&d_bytes) {
            let signing_key = GenericSigningKey::<Sha256, _, _>::new(
                GenericRsaPrivateKey::from_public_and_d(pubkey, d),
            );
            let mut rng = FixedRng(0);
            let mut em = [0u8; 64];
            let mut sig = [0u8; 64];
            let ok = signing_key
                .try_sign_prehash_with_rng_into(&mut rng, &prehash, &mut em, &mut sig)
                .is_ok();
            // Keep the serialized signature live: with only `is_ok()`
            // observed, LLVM may DCE the final serialization writes and
            // the audit would vacuously skip that step.
            black_box(&sig);
            ok
        } else {
            false
        }
    } else {
        false
    };

    unsafe { *out_ptr = black_box(ok as u8) }
}

/// The same audit at the 2048-bit deployment width (`u32` limbs).
/// # Safety
/// `out_ptr` must be a valid pointer to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn panic_audit__pkcs1v15_blinded_sign__fb32__N64(out_ptr: *mut u8) {
    let d_bytes = black_box(D_2048);
    let prehash = black_box([0u8; 32]); // SHA-256 output width.

    let ok = if let Ok(pubkey) = public_key_ct_from_be_bytes::<CarrierW>(&N_2048, 65537) {
        if let Ok(d) = CarrierW::try_from_be_bytes_vartime(&d_bytes) {
            let signing_key = GenericSigningKey::<Sha256, _, _>::new(
                GenericRsaPrivateKey::from_public_and_d(pubkey, d),
            );
            let mut rng = FixedRng(0);
            let mut em = [0u8; 256];
            let mut sig = [0u8; 256];
            let ok = signing_key
                .try_sign_prehash_with_rng_into(&mut rng, &prehash, &mut em, &mut sig)
                .is_ok();
            // Keep the serialized signature live — same DCE rationale as
            // the 512-bit fixture.
            black_box(&sig);
            ok
        } else {
            false
        }
    } else {
        false
    };

    unsafe { *out_ptr = black_box(ok as u8) }
}

/// The same audit at 2048-bit with `u8` limbs (AVR-class flavor).
/// # Safety
/// `out_ptr` must be a valid pointer to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn panic_audit__pkcs1v15_blinded_sign__fb8__N256(out_ptr: *mut u8) {
    let d_bytes = black_box(D_2048);
    let prehash = black_box([0u8; 32]); // SHA-256 output width.

    let ok = if let Ok(pubkey) = public_key_ct_from_be_bytes::<CarrierW8>(&N_2048, 65537) {
        if let Ok(d) = CarrierW8::try_from_be_bytes_vartime(&d_bytes) {
            let signing_key = GenericSigningKey::<Sha256, _, _>::new(
                GenericRsaPrivateKey::from_public_and_d(pubkey, d),
            );
            let mut rng = FixedRng(0);
            let mut em = [0u8; 256];
            let mut sig = [0u8; 256];
            let ok = signing_key
                .try_sign_prehash_with_rng_into(&mut rng, &prehash, &mut em, &mut sig)
                .is_ok();
            black_box(&sig);
            ok
        } else {
            false
        }
    } else {
        false
    };

    unsafe { *out_ptr = black_box(ok as u8) }
}

/// The same audit at 2048-bit with `u64` limbs (64-bit-host flavor).
/// # Safety
/// `out_ptr` must be a valid pointer to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn panic_audit__pkcs1v15_blinded_sign__fb64__N32(out_ptr: *mut u8) {
    let d_bytes = black_box(D_2048);
    let prehash = black_box([0u8; 32]); // SHA-256 output width.

    let ok = if let Ok(pubkey) = public_key_ct_from_be_bytes::<CarrierW64>(&N_2048, 65537) {
        if let Ok(d) = CarrierW64::try_from_be_bytes_vartime(&d_bytes) {
            let signing_key = GenericSigningKey::<Sha256, _, _>::new(
                GenericRsaPrivateKey::from_public_and_d(pubkey, d),
            );
            let mut rng = FixedRng(0);
            let mut em = [0u8; 256];
            let mut sig = [0u8; 256];
            let ok = signing_key
                .try_sign_prehash_with_rng_into(&mut rng, &prehash, &mut em, &mut sig)
                .is_ok();
            black_box(&sig);
            ok
        } else {
            false
        }
    } else {
        false
    };

    unsafe { *out_ptr = black_box(ok as u8) }
}

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
