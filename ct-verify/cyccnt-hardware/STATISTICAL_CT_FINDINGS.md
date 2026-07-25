# RSA-512 statistical DWT and ETM findings

> **Superseded — the key-dependent difference below does NOT reproduce on
> current code.** A same-session rig comparison (see `LOCALIZATION_ANALYSIS.md`)
> ran both a per-stage raw-DWT localizer and the paired-suite Welch test on
> identical current code: the sign is A ≈ B within ≤18 cycles across every
> sub-stage (`pow_d`, `invert_r`, all Montgomery ops Δ0), and the paired-suite
> Welch is `t=1.000` (BelowThreshold, PASS). The ~28K / `t=77998` recorded here
> came from an older artifact and is no longer present. Kept as a point-in-time
> record; the operative result is the localization analysis.

## Verdict (historical — superseded, see banner)

The 100-sample-per-class DWT campaign detects a repeatable key-dependent cycle
difference in the current RSA-512 blinded-signing fixture. The deliberately
variable-time early-exit control is also detected, confirming that the complete
target acquisition and host analysis path is sensitive to a known distinction.

The earlier ETM campaign remains useful complementary evidence, but it used a
different single-trial ELF. The combined report consequently classifies the
two artifacts as incomparable and does not manufacture one joint verdict.

## Statistical DWT evidence

The hardware campaign used the STM32F407VG J-Trace reference board at a
qualified 168 MHz clock, balanced ABBA/BAAB acquisition, and 100 samples for
each A/B class.

| Fixture | Class | Mean A | Mean B | Difference | Welch result |
| --- | --- | ---: | ---: | ---: | --- |
| `pkcs1v15_blinded_sign` | protected `positive` | 128,196,246.36 | 128,168,167.00 | 28,079.36 cycles | `t=77998.222`, exceeds 4.5 |
| `negative_early_exit` | detector `negative` | 582.00 | 73.00 | 509 cycles | deterministic difference |
| `key_construction` | diagnostic `public-setup` | 1,725,050.75 | 1,689,603.75 | 35,447 cycles | `t=115189.116`, exceeds 4.5 |

The protected signing ranges are disjoint (`128,196,246..128,196,282` versus
`128,168,167..128,168,167`). This also fails the pre-existing deterministic
32-cycle maximum-spread policy, independently of Welch analysis. Both signing
paths produced valid output and consumed the same number of deterministic RNG
words.

This is a finding about the current fixture/build, not yet a root-cause claim
about the cryptographic implementation. The crypto implementation owner should
determine whether the difference is in key-dependent arithmetic, fixture setup,
or another reviewed component inside the measured signing boundary.

## ETM evidence retained alongside it

The prior two-key, three-repetition ETM campaign reported:

- identical 142,389,660-cycle DWT checkpoints in all six ETM trials;
- maximum within-key compact-profile distance of 92;
- maximum cross-key compact-profile distance of 1,827;
- a strict ETM profile-invariance failure, without proof of an ordinary
  secret-dependent branch.

Those numbers came from the dedicated `etm-single-trial` ELF. They must not be
treated as execution-profile evidence for the statistical DWT ELF.

## Combined-report qualification

`cargo krabi-caliper combine-ct-evidence` now places campaign Welch evidence
and J-Trace evidence in one JSON/Markdown model and byte-compares their ELFs.
For these two runs it reports:

```text
Combined verdict: IncomparableArtifacts
Identical ELF: false
DWT campaign verdict: WorkloadFail
ETM strict-invariance verdict: FAIL
```

The next fixture-level step, if one joint verdict is required, is to make the
ordinary statistical campaign and debugger-selected ETM trial coexist in one
firmware image. Until then, the separate findings above are the defensible
result.
