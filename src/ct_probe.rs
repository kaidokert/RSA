//! Feature-gated cycle-probe hook for constant-time *measurement* builds.
//!
//! Off by default and a no-op unless `ct-cycle-probe` is enabled, so shipped
//! builds carry nothing. When enabled, a consumer registers a `fn(u32)` with
//! [`set_probe`]; the blinded private op calls [`mark`] at each sub-stage
//! boundary so a hardware harness (e.g. a Cortex-M DWT reader) can localize
//! which stage a per-key timing delta lands in. The probe cost is identical on
//! every call, so it cancels when comparing two keys' per-stage deltas.

#[cfg(feature = "ct-cycle-probe")]
use core::sync::atomic::{AtomicUsize, Ordering};

/// Registered probe, stored as a `fn(u32)` reinterpreted as `usize` (0 = none).
#[cfg(feature = "ct-cycle-probe")]
static PROBE: AtomicUsize = AtomicUsize::new(0);

/// Register the stage callback for a measurement run. Single-core measurement
/// use only — set once before the measured region.
#[cfg(feature = "ct-cycle-probe")]
pub fn set_probe(probe: fn(u32)) {
    PROBE.store(probe as usize, Ordering::Relaxed);
}

/// Emit a stage marker. No-op unless a probe is registered.
#[cfg(feature = "ct-cycle-probe")]
#[inline(always)]
pub fn mark(stage: u32) {
    let raw = PROBE.load(Ordering::Relaxed);
    if raw != 0 {
        // SAFETY: `raw` is non-zero only after `set_probe` stored a valid
        // `fn(u32)` here, so reinterpreting it back is sound.
        let probe: fn(u32) = unsafe { core::mem::transmute(raw) };
        probe(stage);
    }
}

/// No-op marker for the default (non-measurement) build.
#[cfg(not(feature = "ct-cycle-probe"))]
#[inline(always)]
pub fn mark(_stage: u32) {}

/// Stage identifiers emitted by the blinded private op, in execution order.
pub mod stage {
    /// Random blinding factor `r` sampled (`try_random_mod`).
    pub const SAMPLE_R: u32 = 0;
    /// `r` converted to Montgomery form.
    pub const R_TO_MONTY: u32 = 1;
    /// `r⁻¹ mod n` computed (`invert_ct`, safegcd).
    pub const INVERT_R: u32 = 2;
    /// `r^e` computed (public exponent).
    pub const R_POW_E: u32 = 3;
    /// Ciphertext/message `c` converted to Montgomery form.
    pub const C_TO_MONTY: u32 = 4;
    /// Base blinded: `c · r^e`.
    pub const BLIND_MUL: u32 = 5;
    /// Private exponentiation `(c·r^e)^d` — the CT ladder in `d`.
    pub const POW_D: u32 = 6;
    /// Unblinded: `· r⁻¹`.
    pub const UNBLIND_MUL: u32 = 7;
    /// Result retrieved from Montgomery form.
    pub const RETRIEVE: u32 = 8;
    /// Verify-after-sign recompute + compare.
    pub const VERIFY: u32 = 9;
}
