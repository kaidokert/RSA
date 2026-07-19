//! Constant-time verification fixtures for `rsa_heapless`.
//!
//! Each `#[no_mangle] pub unsafe extern "C"` symbol pins one instantiation of
//! a secret-dependent code path so the driver (`ct-driver`) can
//! disassemble it per target ISA and the taint harness (`ct-ctgrind`)
//! can run it under Valgrind with the private inputs marked undefined.
//!
//! Everything reaches the CT surface through the public deployment API
//! (`GenericSigningKey::try_sign_with_rng_into`), so no `rsa_heapless`
//! source is instrumented. The one discipline these fixtures must never
//! break: wrap every secret input and every output in
//! [`core::hint::black_box`], or fat-LTO `opt-level="z"` folds the body
//! into an ABI stub and the inspection passes vacuously.
//!
//! Naming contract the drivers key off:
//! - `ct_fix__<op>__<carrier>` — a positive; its emitted code must be
//!   branch-free / taint-clean.
//! - `nct_fix__neg__<op>` — a negative control; it MUST trip each gate,
//!   proving the harness still has teeth.

#![cfg_attr(feature = "panic-handler", no_std)]

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

use const_num_traits::Ct;
use core::hint::black_box;
use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_ct_from_be_bytes;
use rsa::pkcs1v15::GenericSigningKey;
use rsa::traits::FixedWidthUnsignedInt;
use rsa::GenericRsaPrivateKey;
use sha2::Sha256;

/// 512-bit Ct carrier (`u8` limbs — the most portable backend, and the
/// width the PR-gate taint run uses).
type Carrier = FixedUInt<u8, 64, Ct>;

/// 2048-bit Ct carrier (`u32` limbs) — the deployment width. The gates
/// verify fixture instantiations, not generic code, so the width we
/// actually ship needs its own whole-operation fixture.
type CarrierW = FixedUInt<u32, 64, Ct>;

/// 2048-bit Ct carrier (`u8` limbs) — the AVR-class deployment shape
/// at the same width. Limb width changes which per-limb code folds
/// (the fixed-bigint 0.5.0 `holder_be` panic was invisible at `u8`,
/// real at `u32`), so each shipped flavor gets its own instantiation.
type CarrierW8 = FixedUInt<u8, 256, Ct>;

/// 2048-bit Ct carrier (`u64` limbs) — the natural shape for 64-bit
/// host consumers. Not a footprint-suite target, but it exercises the
/// widest per-limb paths (double-word `u128` intermediates).
type CarrierW64 = FixedUInt<u64, 32, Ct>;

// Real RSA keypairs (`e = 65537`) shared with `panic-free-audit` via a
// textual include — see the fragment's module docs. `D_*` are `pub` so
// the taint harness can copy each secret exponent into a buffer and
// mark that buffer undefined: Valgrind taint is metadata, the real
// bytes must be present for the happy path to run while their V-bits
// carry the "secret" mark.
include!("../../../tests/fixtures/test_keys.rs");

/// Deterministic infallible RNG. The blinded sign path draws the
/// blinding factor `r` from it; a fixed stream keeps taint attribution
/// deterministic (the driver decides pass/fail per symbol, so the
/// stream just needs to be stable, not cryptographic).
struct FixedRng(u64);

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        // SplitMix64 — tiny, deterministic, good enough for a stub.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for FixedRng {}

/// Positive: the whole blinded PKCS#1 v1.5 sign pipeline at 512-bit,
/// driven by the secret private exponent `d`. Exercises padding,
/// `rsa_private_op_and_check_blinded` (→ random-mod sampling → blinded
/// `c^d` → `InvertCt`/`MulCt`), verify-after-sign, and serialization —
/// the composition the primitive-level fixtures one layer down can't
/// see.
/// # Safety
/// `d_ptr` and `out_ptr` must be valid, aligned pointers to 64-byte
/// arrays.
#[no_mangle]
pub unsafe extern "C" fn ct_fix__pkcs1v15_blinded_sign__fb8__N64(
    d_ptr: *const [u8; 64],
    out_ptr: *mut [u8; 64],
) {
    let d_bytes = black_box(unsafe { *d_ptr });

    let pubkey = public_key_ct_from_be_bytes::<Carrier>(&N_512, 65537).unwrap();
    let d = Carrier::try_from_be_bytes_vartime(&d_bytes).unwrap();
    let signing_key =
        GenericSigningKey::<Sha256, _, _>::new(GenericRsaPrivateKey::from_public_and_d(pubkey, d));

    let mut rng = FixedRng(0);
    let mut em = [0u8; 64];
    let mut sig = [0u8; 64];
    let _ = signing_key.try_sign_with_rng_into(&mut rng, b"ct fixture message", &mut em, &mut sig);

    unsafe { *out_ptr = black_box(sig) }
}

/// Positive: the same whole blinded sign pipeline at the 2048-bit
/// deployment width (`u32` limbs). Closes the "fixture instantiations,
/// not generic code" gap: the 512-bit fixture proves the composition,
/// this one proves it at the width we actually ship.
/// # Safety
/// `d_ptr` and `out_ptr` must be valid, aligned pointers to 256-byte
/// arrays.
#[no_mangle]
pub unsafe extern "C" fn ct_fix__pkcs1v15_blinded_sign__fb32__N64(
    d_ptr: *const [u8; 256],
    out_ptr: *mut [u8; 256],
) {
    let d_bytes = black_box(unsafe { *d_ptr });

    let pubkey = public_key_ct_from_be_bytes::<CarrierW>(&N_2048, 65537).unwrap();
    let d = CarrierW::try_from_be_bytes_vartime(&d_bytes).unwrap();
    let signing_key =
        GenericSigningKey::<Sha256, _, _>::new(GenericRsaPrivateKey::from_public_and_d(pubkey, d));

    let mut rng = FixedRng(0);
    let mut em = [0u8; 256];
    let mut sig = [0u8; 256];
    let _ = signing_key.try_sign_with_rng_into(&mut rng, b"ct fixture message", &mut em, &mut sig);

    unsafe { *out_ptr = black_box(sig) }
}

/// Positive: 2048-bit, `u8` limbs — the AVR-class flavor at deployment
/// width.
/// # Safety
/// `d_ptr` and `out_ptr` must be valid, aligned pointers to 256-byte
/// arrays.
#[no_mangle]
pub unsafe extern "C" fn ct_fix__pkcs1v15_blinded_sign__fb8__N256(
    d_ptr: *const [u8; 256],
    out_ptr: *mut [u8; 256],
) {
    let d_bytes = black_box(unsafe { *d_ptr });

    let pubkey = public_key_ct_from_be_bytes::<CarrierW8>(&N_2048, 65537).unwrap();
    let d = CarrierW8::try_from_be_bytes_vartime(&d_bytes).unwrap();
    let signing_key =
        GenericSigningKey::<Sha256, _, _>::new(GenericRsaPrivateKey::from_public_and_d(pubkey, d));

    let mut rng = FixedRng(0);
    let mut em = [0u8; 256];
    let mut sig = [0u8; 256];
    let _ = signing_key.try_sign_with_rng_into(&mut rng, b"ct fixture message", &mut em, &mut sig);

    unsafe { *out_ptr = black_box(sig) }
}

/// Positive: 2048-bit, `u64` limbs — the 64-bit-host flavor.
/// # Safety
/// `d_ptr` and `out_ptr` must be valid, aligned pointers to 256-byte
/// arrays.
#[no_mangle]
pub unsafe extern "C" fn ct_fix__pkcs1v15_blinded_sign__fb64__N32(
    d_ptr: *const [u8; 256],
    out_ptr: *mut [u8; 256],
) {
    let d_bytes = black_box(unsafe { *d_ptr });

    let pubkey = public_key_ct_from_be_bytes::<CarrierW64>(&N_2048, 65537).unwrap();
    let d = CarrierW64::try_from_be_bytes_vartime(&d_bytes).unwrap();
    let signing_key =
        GenericSigningKey::<Sha256, _, _>::new(GenericRsaPrivateKey::from_public_and_d(pubkey, d));

    let mut rng = FixedRng(0);
    let mut em = [0u8; 256];
    let mut sig = [0u8; 256];
    let _ = signing_key.try_sign_with_rng_into(&mut rng, b"ct fixture message", &mut em, &mut sig);

    unsafe { *out_ptr = black_box(sig) }
}

/// Negative control — a secret-dependent *early-exit loop*. MUST trip
/// every gate. A variable-trip-count loop can't be flattened into a
/// branchless select the way a simple `if x { … }` can (which LLVM
/// lowers to `csel`/`cmov` — invisible to a taint tool that only sees
/// conditional *jumps*), so the loop's condition on a tainted byte is a
/// real conditional jump on every target. Counts leading zero bytes;
/// the `break` is the branch. A clean pass here means the harness is
/// broken.
/// # Safety
/// `s_ptr` must be a valid, aligned pointer to a 64-byte array;
/// `out_ptr` to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn nct_fix__neg__secret_branch__fb8__N64(
    s_ptr: *const [u8; 64],
    out_ptr: *mut u8,
) {
    let s = black_box(unsafe { *s_ptr });
    let mut n = 0u8;
    for &b in s.iter() {
        if b != 0 {
            break;
        }
        n = n.wrapping_add(1);
    }
    unsafe { *out_ptr = black_box(n) }
}

/// Negative control — a non-constant-time comparison (lexicographic,
/// early-exit on the first differing byte, like a naive `memcmp`). MUST
/// trip: the early `break` on a tainted byte is a conditional jump that
/// survives optimization on every target.
/// # Safety
/// `s_ptr` must be a valid, aligned pointer to a 64-byte array;
/// `out_ptr` to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn nct_fix__neg__vartime_cmp__fb8__N64(
    s_ptr: *const [u8; 64],
    out_ptr: *mut u8,
) {
    let s = black_box(unsafe { *s_ptr });
    let reference = [0u8; 64];
    let mut equal = 1u8;
    for i in 0..64 {
        if s[i] != reference[i] {
            equal = 0;
            break;
        }
    }
    unsafe { *out_ptr = black_box(equal) }
}

/// No-op that forces this rlib onto a consumer's link line. The taint
/// harness links `ct-fixtures` as an rlib and calls its `#[no_mangle]`
/// symbols by name across the C ABI; without a referenced Rust item the
/// linker may drop the rlib entirely (and with it every fixture symbol).
pub fn link_anchor() {}
