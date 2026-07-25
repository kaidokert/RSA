# RSA-512 signing: localization + attribution of the key-dependent cycle delta

`STATISTICAL_CT_FINDINGS.md` records a reproducible ~28,079-cycle difference
between signing key A and key B (`t=77998`, disjoint ranges, fails the 32-cycle
spread policy). This note attributes that delta from the source, then adds an
on-rig localizer to name the exact operation.

## Hardware result (STM32F407 @ 168 MHz, DWT)

Per-stage A-vs-B deltas from the `localize` fixture on the rig:

| stage | A | B | Δ |
| --- | ---: | ---: | ---: |
| sample_r (+ hash/pad/setup) | 33,412 | 33,397 | 15 |
| r_to_monty | 216,829 | 216,829 | 0 |
| invert_r (safegcd) | 100,040,792 | 100,040,792 | 0 |
| r_pow_e | 10,549,870 | 10,549,870 | 0 |
| c_to_monty | 216,803 | 216,803 | 0 |
| blind_mul | 12,017 | 12,017 | 0 |
| pow_d (secret ladder) | 20,434,953 | 20,434,953 | 0 |
| unblind_mul | 12,017 | 12,017 | 0 |
| retrieve | 121,334 | 121,334 | 0 |
| verify | 10,890,300 | 10,890,300 | 0 |

`rng_words` 32/32, both signs valid. **Every internal stage is cycle-identical
between the two keys** — including `pow_d` and `invert_r` — confirming the static
attribution on hardware. The only non-zero delta is 15 cycles in the
RNG-sample/setup bucket (noise; `n`-keyed sampling, not secret).

Crucially, this means the ~28K the statistical DWT campaign reported is **not in
the sign**. Both the localizer and the campaign call the same `sign_once`;
bracketed directly it is A = B to within 15 cycles. The 28K is introduced by the
paired-suite acquisition (its ~128M measured base differs from the ~142M whole
sign), i.e. the measurement harness — not the cryptographic operation. The
follow-up, if any, is to audit the paired-suite A/B boundary, not the crypto.

## Bottom line

**Not a private-exponent (`d`) side-channel.** Every `d`-dependent step in the
blinded PKCS#1 v1.5 sign is fixed-iteration with branchless, full-width
selects/compares. The two signing inputs differ only in `n` (public) and `d`
(secret), and `c` (the padded message) is *identical* between keys — so the
delta can only be `n`-driven (public modulus / sampled `r`) or a
measurement/microarchitectural artifact. Both are benign for the
"constant-time in the private exponent" claim.

## Attribution — every secret-dependent path is constant-iteration

Sign path: `try_sign_with_rng_into` → `algorithms::pkcs1v15::sign_with_rng_into`
→ `algorithms::rsa::rsa_private_op_and_check_blinded` → `rsa_private_op_blinded`.

| Step | Where | `d`/secret dependence |
| --- | --- | --- |
| padded message → field element `c` | `algorithms/pkcs1v15.rs:297` (`try_from_be_bytes_vartime`) | none — fixed-width byte copy; `c` is **identical** for both keys (same message, same `k=64`) |
| sample `r` | `rsa_private_op_and_check_blinded` → `TryRandomMod` | `n`-keyed (public); RNG stream identical (same seed), and the finding confirms equal `rng_words` (equal draws) |
| `r⁻¹ mod n` | `safegcd_inv_ct` (modmath `inv/safegcd.rs:282`) | **fixed** `divsteps_total(bits_precision)` iterations (`:305–331`); runs the full count even for the None case |
| `r^e` | `pow_bounded_exp(e, e.bits())` (`algorithms/rsa.rs:388`) | `e = 65537` is **public** and identical for both keys |
| `c·r^e`, `s'·r⁻¹` | `mul_ct` (CIOS-Ct) | fixed limb count; final conditional subtraction is a `conditional_select`, not a branch |
| `s' = blinded^d` | `pow(d)` → `pow_loop_ct` (modmath `field.rs:799`) | **fixed** `w = bits_precision` iterations (`:803`), `conditional_select` per bit — independent of `d`'s value/bit-length |
| verify-after-sign `c != check` | `algorithms/rsa.rs:449` | `Ord::cmp`/`PartialEq` on the `Ct` carrier is `const_cmp_ct` — full-width, no short-circuit (fixed-bigint `fixeduint.rs:345`) |

The two primitives that would carry a classic RSA timing leak are verified
fixed-iteration from the **public** width, not the secret value:

- exponent ladder — `pow_loop_ct`: `for i in (0..w).rev()` with
  `w = max(exp.bits_precision(), modulus.bits_precision())`, `conditional_select`
  per bit. `d`'s bit-length does not change the iteration count.
- modular inverse — `safegcd_inv_ct`: `for _ in 0..divsteps_total(n_bits)` with
  `n_bits = max(value.bits_precision(), modulus.bits_precision())`.

And the branchless idioms are genuinely branchless:
`FixedUInt<T,N,Ct>::conditional_select` (fixeduint.rs:334) iterates all `N` limbs
with per-limb mask select; `Ct` comparisons scan full width with no
short-circuit. So `d` reaches only the *choice* inputs of constant-time selects
— it cannot move the cycle count.

Magnitude corroborates: 28K is ~0.1 of a single ladder iteration (~250K
cyc/iter at this width). An exponent-length leak would appear as *integer
multiples* of an iteration, not a sub-iteration constant.

## The anomaly worth naming on the rig

Under the static model a **same-width** sign should be cycle-*identical*
between keys: all `d`-paths are constant-iteration, `c` is identical, and the
Montgomery constants (`n'`, `R² mod n`) are precomputed at key construction (a
separate diagnostic stage), not inside the measured sign. `n` changes operand
*values*, not operation *counts*, and Cortex-M4 ALU/multiply timing is
value-independent — so a 28K reproducible delta is not predicted by the model.

That means the delta is one of:
1. an `n`-driven variable *operation count* in a primitive (public → benign), or
2. a value-dependent effect in a "branchless" primitive that the iteration
   structure hides (would need a specific op named), or
3. a measurement/microarchitectural artifact.

None of these is a `d` leak, but (2) is worth excluding empirically. Hence the
localizer below.

## On-rig localizer (`--features localize`)

Rather than reconstruct the op from public primitives (some, like `Pow`, aren't
exported), the localizer times the **real** path. `rsa_heapless` gains an
off-by-default `ct-cycle-probe` feature (`src/ct_probe.rs`): the blinded op
calls `ct_probe::mark(stage)` at each of the ten sub-stage boundaries
(`SAMPLE_R … VERIFY`), and a consumer registers a `fn(u32)` probe with
`ct_probe::set_probe`. The `localize` fixture feature registers a probe that
records `DWT::cycle_count()` per stage, signs key A then key B once each (after
a warm-up sign), and prints per-stage A-vs-B deltas over RTT as
`LOCALIZE_STAGE name:… a:… b:… delta:…`. The probe cost is identical on every
call, so it cancels in the delta; the whole hook compiles to nothing in shipped
builds.

Run it on the rig board:

```sh
cargo build --release --target thumbv7em-none-eabihf \
  --no-default-features \
  --features clock-168mhz,rsa512,carrier-u32x16,localize
# flash + read RTT; each LOCALIZE_STAGE line is one sub-op's A-vs-B cycle delta
```

Whichever stage's `delta` carries the ~28K names the operation. `pow_d` is
included even though it's proven constant above — a non-zero delta there would
contradict the proof and be a genuine finding; a ~zero delta there confirms it.
A delta of ~0 across *all* stages would place the difference outside the private
op (padding / hash / serialization in `try_sign_with_rng_into`).
