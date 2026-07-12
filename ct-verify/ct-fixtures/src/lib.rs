//! Constant-time verification fixtures for `rsa_heapless`.
//!
//! Each `#[no_mangle] pub extern "C"` symbol pins one instantiation of
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

#![no_std]

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
/// width the taint layer runs at; deployment-width fixtures come later).
type Carrier = FixedUInt<u8, 64, Ct>;

/// A real 512-bit RSA keypair (`e = 65537`). The values must be a valid
/// keypair so the blinded-sign happy path (with its verify-after-sign)
/// is the code under inspection rather than the retry-then-fail path.
const N_512: [u8; 64] = [
    0x9f, 0x7b, 0x0d, 0x2e, 0xfb, 0x10, 0xd4, 0x1b, 0x8c, 0x86, 0x0f, 0x90, 0x67, 0xee, 0xbd, 0xd4,
    0x72, 0x2d, 0x7e, 0x9f, 0xc2, 0x3b, 0x95, 0x34, 0x33, 0x92, 0x09, 0xf9, 0x0f, 0xa8, 0xf7, 0xed,
    0xf7, 0x49, 0xd0, 0x42, 0x31, 0xff, 0x52, 0x2e, 0xb0, 0xf6, 0x89, 0xfe, 0xc4, 0x75, 0x35, 0x1c,
    0x2c, 0x76, 0x53, 0xaa, 0xa1, 0x4a, 0x05, 0xb3, 0xd9, 0x42, 0x6e, 0x41, 0xc4, 0xd8, 0xe4, 0x6f,
];
/// The paired secret exponent, exported so the taint harness can copy
/// it into a buffer and mark that buffer undefined — Valgrind taint is
/// metadata, so the real bytes must be present for the happy path to
/// run while their V-bits carry the "secret" mark.
pub const D_512: [u8; 64] = [
    0x10, 0x44, 0x80, 0x02, 0xc3, 0xcf, 0x62, 0xa3, 0x70, 0xc1, 0x18, 0x03, 0x55, 0xe6, 0xaf, 0x6c,
    0x65, 0x3d, 0x28, 0xc6, 0x69, 0x0c, 0xa4, 0xda, 0x8f, 0x4c, 0x1d, 0x42, 0x4f, 0x8b, 0x9f, 0xc6,
    0x78, 0x0a, 0x6d, 0x42, 0xf4, 0xce, 0x9a, 0x37, 0x83, 0xf5, 0xf4, 0x59, 0x71, 0xb3, 0x8f, 0x5e,
    0x1b, 0x70, 0xbe, 0xbb, 0x91, 0xd6, 0x74, 0xd8, 0x9c, 0xae, 0xc7, 0xd1, 0x3b, 0x8c, 0xaa, 0x39,
];

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
#[no_mangle]
pub extern "C" fn ct_fix__pkcs1v15_blinded_sign__fb8__N64(
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

/// Negative control — data-dependent branch on a secret byte. MUST
/// trip every gate (asm-grep sees the conditional branch; taint sees
/// the secret-flagged jump). A clean pass here means the harness is
/// broken.
#[no_mangle]
pub extern "C" fn nct_fix__neg__secret_branch__fb8__N64(s_ptr: *const [u8; 64], out_ptr: *mut u8) {
    let s = black_box(unsafe { *s_ptr });
    let mut acc = 0u8;
    // Branch whose taken/not-taken depends on secret bytes.
    for &b in s.iter() {
        if b > 0x7f {
            acc = acc.wrapping_add(b);
        }
    }
    unsafe { *out_ptr = black_box(acc) }
}

/// Negative control — variable-time remainder on a secret dividend.
/// MUST trip: `%` on a runtime value lowers to a data-dependent
/// division/branch sequence on every target the driver covers.
#[no_mangle]
pub extern "C" fn nct_fix__neg__vartime_rem__fb8__N64(s_ptr: *const [u8; 8], out_ptr: *mut u64) {
    let s = u64::from_le_bytes(black_box(unsafe { *s_ptr }));
    let r = black_box(s) % black_box(0x1_0000_000du64);
    unsafe { *out_ptr = black_box(r) }
}
