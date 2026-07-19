//! Taint wrappers, one per `ct-fixtures` symbol. Each mirrors its
//! fixture's ABI one-for-one; extending the fixture set means adding
//! the symbol there and the matching wrapper here.
//!
//! Taint model: the RSA private exponent `d` is the secret. The
//! modulus `n`, public exponent `e`, and message are public (baked into
//! the fixture), so they are not tainted — a secret-dependent branch
//! anywhere in the reachable sign path (including inlined modmath /
//! fixed-bigint primitives) trips memcheck, while the many legitimate
//! branches on public lengths / key structure pass by construction.
//!
//! The signature output is untainted before we `black_box` it: an RSA
//! signature is secret-*derived* but public-by-design (it is what the
//! caller publishes), so reads of it downstream are not leaks.

use core::hint::black_box;
use krabi_caliper::ctgrind_fixture;
use krabi_caliper::host::ctgrind::{taint_val, untaint_val};

// Positive: the whole blinded PKCS#1 v1.5 sign at 512-bit, driven by
// the secret `d`. `ct-fixtures::D_512` is the real private exponent, so
// the blinded-sign happy path (with verify-after-sign) is what runs;
// Valgrind's V-bits carry the "secret" mark, the bytes stay real.
unsafe extern "C" {
    fn ct_fix__pkcs1v15_blinded_sign__fb8__N64(d_ptr: *const [u8; 64], out_ptr: *mut [u8; 64]);
}
ctgrind_fixture!(ct_fix__pkcs1v15_blinded_sign__fb8__N64, {
    let d = ct_fixtures::D_512;
    let mut out = [0u8; 64];
    taint_val(&d);
    unsafe { ct_fix__pkcs1v15_blinded_sign__fb8__N64(&d, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

// Positive: the same pipeline at the 2048-bit deployment width (`u32`
// limbs) — closes the "fixture instantiations, not generic code" gap
// at the width the crate actually ships.
unsafe extern "C" {
    fn ct_fix__pkcs1v15_blinded_sign__fb32__N64(d_ptr: *const [u8; 256], out_ptr: *mut [u8; 256]);
}
ctgrind_fixture!(ct_fix__pkcs1v15_blinded_sign__fb32__N64, {
    let d = ct_fixtures::D_2048;
    let mut out = [0u8; 256];
    taint_val(&d);
    unsafe { ct_fix__pkcs1v15_blinded_sign__fb32__N64(&d, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

// Positive: 2048-bit, `u8` limbs — the AVR-class flavor at deployment
// width.
unsafe extern "C" {
    fn ct_fix__pkcs1v15_blinded_sign__fb8__N256(d_ptr: *const [u8; 256], out_ptr: *mut [u8; 256]);
}
ctgrind_fixture!(ct_fix__pkcs1v15_blinded_sign__fb8__N256, {
    let d = ct_fixtures::D_2048;
    let mut out = [0u8; 256];
    taint_val(&d);
    unsafe { ct_fix__pkcs1v15_blinded_sign__fb8__N256(&d, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

// Positive: 2048-bit, `u64` limbs — the 64-bit-host flavor.
unsafe extern "C" {
    fn ct_fix__pkcs1v15_blinded_sign__fb64__N32(d_ptr: *const [u8; 256], out_ptr: *mut [u8; 256]);
}
ctgrind_fixture!(ct_fix__pkcs1v15_blinded_sign__fb64__N32, {
    let d = ct_fixtures::D_2048;
    let mut out = [0u8; 256];
    taint_val(&d);
    unsafe { ct_fix__pkcs1v15_blinded_sign__fb64__N32(&d, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

// Negative control: a data-dependent branch on the secret bytes. MUST
// trip — memcheck sees the tainted early-exit loop condition.
unsafe extern "C" {
    fn nct_fix__neg__secret_branch__fb8__N64(s_ptr: *const [u8; 64], out_ptr: *mut u8);
}
ctgrind_fixture!(nct_fix__neg__secret_branch__fb8__N64, {
    let s = [0u8; 64];
    let mut out = 0u8;
    taint_val(&s);
    unsafe { nct_fix__neg__secret_branch__fb8__N64(&s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});

// Negative control: a non-constant-time (early-exit) comparison on the
// secret bytes. MUST trip.
unsafe extern "C" {
    fn nct_fix__neg__vartime_cmp__fb8__N64(s_ptr: *const [u8; 64], out_ptr: *mut u8);
}
ctgrind_fixture!(nct_fix__neg__vartime_cmp__fb8__N64, {
    let s = [0u8; 64];
    let mut out = 0u8;
    taint_val(&s);
    unsafe { nct_fix__neg__vartime_cmp__fb8__N64(&s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});
