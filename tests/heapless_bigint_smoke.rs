//! EXPERIMENT (bigint-heapless-runtime-len): compile/link smoke test for
//! the runtime-length carrier inside this crate's dependency graph.
//!
//! `fixed_bigint::HeaplessBigInt` is the new fixed-capacity /
//! runtime-length bignum this experiment exists to adopt. This test
//! pins two things, host-only:
//!
//! 1. The carrier and the const-num-traits 0.2.1 vocabulary surface
//!    (`BitWidth` = bit-length, `BitsPrecision` = constructed width)
//!    compile, link, and behave next to the rsa crate.
//! 2. The porting gap is explicit: `HeaplessBigInt` does NOT yet
//!    satisfy this crate's carrier traits. When the port lands, the
//!    `assert_not_impl_any!` below fails to compile and must be
//!    flipped — the test is a progress marker, not just a smoke check.

use const_num_traits::{BitWidth, BitsPrecision, Ct, Nct};
use fixed_bigint::HeaplessBigInt;

/// 2048-bit capacity carrier (`u32` limbs × 64) — the deployment shape
/// the experiment targets: one binary, many runtime widths.
type H = HeaplessBigInt<u32, 64>;
type HCt = HeaplessBigInt<u32, 64, Ct>;

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

#[test]
fn ct_personality_constructs() {
    let v = HCt::from_be_bytes(&[0xAB; 8]);
    assert_eq!(v.len(), 2);
    assert_eq!(BitsPrecision::bits_precision(v), 64);
}

// ── The porting gap, pinned ─────────────────────────────────────────
//
// The carrier deliberately does not implement `PrimBits` (a fixed-width
// census surface), so it doesn't reach `FixedWidthUnsignedInt`'s
// blanket impl and is not yet an `UnsignedModularInt`. When the
// experiment wires it in, these assertions break the build — update
// them to `assert_impl_all!` and start deleting the scaffolding above.
mod porting_gap {
    use super::*;
    use rsa::traits::{FixedWidthUnsignedInt, UnsignedModularInt};
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(H: FixedWidthUnsignedInt, UnsignedModularInt);
    assert_not_impl_any!(HCt: FixedWidthUnsignedInt, UnsignedModularInt);
    assert_not_impl_any!(HeaplessBigInt<u32, 64, Nct>: FixedWidthUnsignedInt, UnsignedModularInt);
}
