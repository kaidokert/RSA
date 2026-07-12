//! Linker-DCE audit for the heapless sign path.
//!
//! The `#[no_mangle] pub extern "C"` symbol exercises the whole
//! heapless PKCS#1 v1.5 sign the way a deployed consumer would: fallible
//! key construction handled with `if let Ok` (a `match`, never a
//! panicking `unwrap`), and the sign `Result` observed through
//! `black_box` rather than extracted. After cross-building with the
//! workspace release profile, `check.sh` asserts the archive contains
//! no `core::panicking` machinery — for a signer a reachable panic is
//! both a DoS edge and a timing oracle (the panic-formatting path's cost
//! depends on the values being formatted).
//!
//! The *prehash* sign variant is used so the digest compression (public,
//! upstream `sha2`) stays out of the archive; the audit is scoped to
//! this crate's composition — PKCS#1 v1.5 padding, the blinded private
//! op, verify-after-sign, and serialization.

// no_std + the local #[panic_handler] only under the `panic-handler`
// feature (the cross-built audit shape, enabled by check.sh). Host-side
// workspace builds (clippy) link std, which supplies its own.
#![cfg_attr(feature = "panic-handler", no_std)]

use const_num_traits::Ct;
use core::hint::black_box;
use fixed_bigint::FixedUInt;
use rsa::modmath_support::public_key_ct_from_be_bytes;
use rsa::pkcs1v15::GenericSigningKey;
use rsa::traits::FixedWidthUnsignedInt;
use rsa::GenericRsaPrivateKey;
use sha2::Sha256;

type Carrier = FixedUInt<u8, 64, Ct>;

// A real 512-bit RSA keypair (e = 65537), so construction succeeds and
// the sign path is actually reached rather than skipped by `if let Ok`.
const N_512: [u8; 64] = [
    0x9f, 0x7b, 0x0d, 0x2e, 0xfb, 0x10, 0xd4, 0x1b, 0x8c, 0x86, 0x0f, 0x90, 0x67, 0xee, 0xbd, 0xd4,
    0x72, 0x2d, 0x7e, 0x9f, 0xc2, 0x3b, 0x95, 0x34, 0x33, 0x92, 0x09, 0xf9, 0x0f, 0xa8, 0xf7, 0xed,
    0xf7, 0x49, 0xd0, 0x42, 0x31, 0xff, 0x52, 0x2e, 0xb0, 0xf6, 0x89, 0xfe, 0xc4, 0x75, 0x35, 0x1c,
    0x2c, 0x76, 0x53, 0xaa, 0xa1, 0x4a, 0x05, 0xb3, 0xd9, 0x42, 0x6e, 0x41, 0xc4, 0xd8, 0xe4, 0x6f,
];
const D_512: [u8; 64] = [
    0x10, 0x44, 0x80, 0x02, 0xc3, 0xcf, 0x62, 0xa3, 0x70, 0xc1, 0x18, 0x03, 0x55, 0xe6, 0xaf, 0x6c,
    0x65, 0x3d, 0x28, 0xc6, 0x69, 0x0c, 0xa4, 0xda, 0x8f, 0x4c, 0x1d, 0x42, 0x4f, 0x8b, 0x9f, 0xc6,
    0x78, 0x0a, 0x6d, 0x42, 0xf4, 0xce, 0x9a, 0x37, 0x83, 0xf5, 0xf4, 0x59, 0x71, 0xb3, 0x8f, 0x5e,
    0x1b, 0x70, 0xbe, 0xbb, 0x91, 0xd6, 0x74, 0xd8, 0x9c, 0xae, 0xc7, 0xd1, 0x3b, 0x8c, 0xaa, 0x39,
];

/// Deterministic infallible RNG for the salt/blinding draw — its stream
/// only needs to be stable, not cryptographic, for a DCE audit.
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
        // Byte-loop fill instead of `copy_from_slice` so the audit
        // harness's own RNG contributes no `len_mismatch_fail` machinery
        // to the archive being measured.
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

/// Whole heapless PKCS#1 v1.5 blinded sign, panic-audited: no `unwrap`
/// on the fallible setup, sign `Result` observed not extracted.
#[no_mangle]
pub extern "C" fn panic_audit__pkcs1v15_blinded_sign__fb8__N64(out_ptr: *mut u8) {
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

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
