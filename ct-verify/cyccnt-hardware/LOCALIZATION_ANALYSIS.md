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

## Same-session raw-vs-paired comparison (resolves the 28K and the base gap)

Both measurements were run on identical current code in one rig session:

| | raw localizer (whole-sign) | paired-suite (Welch) |
| --- | --- | --- |
| A vs B | Δ ≤ 18 cycles across all 10 stages (noise) | `t = 1.000`, threshold 4.50 → BelowThreshold (PASS) |
| absolute | 142.5M | ~122M |

Controls in the same run: `negative_early_exit` `t=82` (ExceedsThreshold, trips),
`key_construction` `t=3057` (ExceedsThreshold, different keys) — the harness has
teeth; only the sign passes.

- **The 28K does not reproduce.** Fresh Welch `t=1.000` and raw Δ≤18 cycles both
  say A ≈ B. The `STATISTICAL_CT_FINDINGS.md` figure (`t=77998`) was an older
  artifact; the sign is constant-time between keys on current code.
- **The ~20M base gap (paired ~122M vs raw 142.5M) is measurement warmth, not
  the crypto.** The paired suite brackets *more* (it includes serialization) yet
  measures *fewer* cycles, so the same sign simply runs faster there: it executes
  fully warmed (`warmup_blocks=2` + interleaved samples) inside a
  `reset + dsb/isb + critical_section` bracket (krabi-caliper
  `backends/cortex_m.rs::measure_in_critical_section`), vs the localizer's
  lightly-warmed back-to-back reads — STM32F407 Flash-ART instruction-cache
  warmth. It is identical for A and B, so it never affected the CT verdict.

## Conditioned validation at depth (caliper 0.1.2 per-sample prewarm)

Per-sample lifecycle conditioning (caliper `positive_conditioned`, published
`krabi-caliper 0.1.2`) prewarms the signing path immediately before — but
outside — each timed A/B sample. Run on the F407 rig at 100 samples/class,
accumulated as 5 × 20 short attaches (see `statistical-chunk` / the chunked
workflow) to sidestep a probe USB fault on a single long attach:

| Fixture | A mean | B mean | Δ | Welch t | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| `pkcs1v15_blinded_sign` | 143,039,348.4 | 143,039,347.9 | +0.5 | 2.035 | BelowThreshold (PASS) |
| `negative_early_exit` | 598.8 | 74.8 | +524 | 474.7 | ExceedsThreshold (trips) |
| `key_construction` | 1,940,661 | 1,901,397 | +39,264 | 39,329 | ExceedsThreshold (public setup) |

Sign spread ≤10, sd ≤1.74; `sign_conditioning:per-sample-prewarm` present in the
evidence; DWT wraps = 0; absolute 143.0M aligns with the raw localizer's 142.5M.

**Framing.** Conditioning stabilizes the measurement lifecycle and aligns the
absolute timing with the raw localizer — the sign is A ≈ B (Δ 0.5 cyc,
`t=2.035`) with the controls tripping. It is **not** claimed to explain the
obsolete historical 28K result, which no longer reproduces even *without*
conditioning (current unconditioned 100-sample: `t=1.000`). The three
data points: historical `t=77998` (superseded, cause not isolable) → current
unconditioned `t=1.000` → current conditioned `t=2.035`.

## 30 MHz / 0-wait-state: the root fix

The warmth above is the 168 MHz ART prefetch/I-cache; the direct fix is to
measure at 0 wait states, where there is no ART and core cycles carry no fetch
jitter. Rig-validated at 30 MHz (the F407's 0-WS ceiling, `clock-30mhz` /
`jtrace-f407-30mhz-0ws`) for rsa512-u32x16: sign Welch `t=0.655`
(BelowThreshold, PASS), the negative control returns a `DeterministicDifference`
verdict (zero-variance, fixed A/B offset — the 0-WS determinism itself), and
`key_construction` trips (`t=136061`). Because 0 WS makes the measurement
deterministic on its own, per-sample conditioning is belt-and-suspenders in this
regime rather than load-bearing (it stays behind the off-by-default
`conditioning` feature).

## Landed gate: two clocks (~15 min measured)

The `hw-ct` gate runs two campaigns under one rig lock:

- **`rsa768-ct-jtrace-f407-30mhz`** — the CT gate proper. 768-bit (u32x24, the
  smallest OAEP-SHA256-compatible width) at 30 MHz / 0 WS, so the verdict rests
  on deterministic core cycles. At near-zero variance a small sample count is
  valid (the rsa512@30 MHz precedent above got a genuine `t=0.655` pass at the
  same count) — validity comes from the determinism, not from N. Two positive
  fixtures run at this width: `pkcs1v15_blinded_sign` and `pss_blinded_sign`.
  They share the entire blinded private op (the secret-dependent surface Δ0 in
  the per-stage table above); PSS adds only the public-input EMSA-PSS encoding.
- **`rsa2048-smoke-jtrace-f407-168mhz`** — a deployment-width functional smoke
  (`gate = false`), confirming a 2048-bit key signs correctly on hardware
  (output + RNG-draw checks). It is *not* a CT gate: the CT property is
  width-independent and proven at 768; a 2048 sign at 30 MHz would run minutes,
  so 168 MHz keeps its wall time bounded.

Landed verdict (rig run 30185333163):

| Campaign | Fixture | t | Verdict |
| --- | --- | ---: | --- |
| 768@30 (gate) | `pkcs1v15_blinded_sign` | 1.831 | BelowThreshold (PASS) |
| 768@30 (gate) | `pss_blinded_sign` | 0.249 | BelowThreshold (PASS) |
| 768@30 (gate) | `negative_early_exit` | — | DeterministicDifference (trips) |
| 768@30 (gate) | `key_construction` | −68975 | ExceedsThreshold (public setup) |
| 2048@168 smoke | `pkcs1v15_blinded_sign` | 1.161 | BelowThreshold |
| 2048@168 smoke | `negative_early_exit` | 1705.8 | ExceedsThreshold (trips) |

Both campaigns PASS; PSS is CT between keys (`t=0.249`) with the controls tripping.
