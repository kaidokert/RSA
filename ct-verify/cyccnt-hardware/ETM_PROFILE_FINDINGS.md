# RSA-512 ETM profile findings

## Verdict

The RSA-512 signing fixture is cycle-constant in this campaign, but its compact
ETM trace signature is not key-invariant.

The measured `1827` cross-key profile distance is real and repeatable, but it
is **not evidence of 1827 differently retired instructions** and does not
currently establish a secret-dependent branch. The appropriate classification
is **ETM trace-profile non-invariance**, not a demonstrated timing leak.

The dominant address-local differences are incompatible with literal retired
instruction counts. For example, `subtle::black_box` is a straight-line
five-instruction basic block. Every invocation must execute all five
instructions, but J-Trace assigned unequal totals to its addresses within the
same trial and across keys. The compact statistics therefore represent
traced-address/event attribution rather than a lossless instruction sequence.

The most plausible interpretation is:

1. The underlying ETM stream differs between keys.
2. Much of the address-level distance is decoder or packet-attribution
   displacement across nearby basic blocks and callees.
3. The likely real source of the ETM-visible distinction is predicated Thumb
   execution (`IT` blocks) used for branchless carries, borrows, and selects,
   plus resulting trace-packet alignment changes—not ordinary
   secret-dependent branching.
4. This is compatible with the exact DWT result: predicated slots and balanced
   branchless paths can expose different predicate outcomes to ETM while
   retaining the same aggregate cycle count.

This gate therefore enforces a stronger property than the crate's usual
cycle-constant and branchless contract. Conditional moves and predicated carry
handling that are normally acceptable constant-time idioms can fail strict ETM
trace invariance.

## Hardware evidence

The final 2026-07-18 J-Trace run used two independent RSA-512 private keys and
three trials per key:

- All six signatures were valid.
- Every trial consumed 40 words from its matched deterministic RNG stream.
- Every target DWT result was exactly 142,389,660 cycles.
- The first DWT result was read directly from target memory and independently
  recovered from the RTT `ETM_TRIAL` record with an exact match.
- Same-key compact-profile distance was at most 92.
- Cross-key compact-profile distance reached 1827.
- 200 of 210 addresses with a nonzero mean key delta had disjoint per-key
  ranges across the three trials.
- The staged and flashed ELF had the same SHA-256 digest as the measured
  release artifact:
  `9c55e9d408f7bca7fecff042ed519c047da457f438838bd8ba6bcff3138ca7b8`.

The key separation is repeatable even though the individual address totals
cannot be interpreted as exact instruction execution counts.

## Difference classification

| Family | Mean-profile L1 contribution | Classification |
| --- | ---: | --- |
| `FixedUInt::shr` | 506.3 | Attribution displacement. The CT barrel shifter always iterates every public `usize` bit and every limb; its loop path is independent of the secret shift amount. Counts at its fixed loop branches do not preserve the ratios required by the disassembly. |
| `compiler_builtins::memcpy` | 287.3 | Mostly attribution or caller-context displacement. Its local branches depend on length and alignment, while the fixture has deterministic stack layout and fixed-size values. This is not independent evidence of secret-addressed memory. |
| `subtle::black_box` | 142.0 | Definitive non-literal attribution. It is one straight-line five-instruction function, yet the reported address totals are unequal. |
| `ConditionallySelectable` | 139.0 | Branchless balanced-path behavior plus attribution. It runs a fixed 16-limb loop and selects with masks; the emitted function contains no secret branch. |
| `ConstantTimeLess` | 135.0 | Fixed-loop branchless comparison. Loop trip counts are public and secret comparison state is propagated arithmetically. Address deltas cannot be read as differing loop counts. |
| `sign_once` | 86.0 over 50 addresses | Diffuse downstream attribution, not one localized branch. Setup and error branches take the same successful path in every validated trial. |
| `wide_mul` | 58.0 | Mostly public-index loop control, with Thumb `IT` blocks including carry-dependent conditional moves and stores. This is a plausible source of ETM-visible predicate differences without cycle differences. |
| `wrapping_sub` | 56.0 | Fixed 16-limb loop with borrow-dependent `IT`/`movlo` instructions. This is a plausible genuine predicate-outcome difference, not a control-flow branch. |
| CIOS Montgomery multiplication | 46.0 | Fixed loop bounds with borrow-dependent `IT`/`movlo` final-reduction logic. This is a plausible genuine predicate-outcome difference; the final value is selected without branching. |
| safegcd helpers | About 50 combined | Source uses fixed divstep counts and `ConditionallySelectable`. The differences likely reflect secret `Choice` values and downstream predication, not early exit. |
| bounded exponentiation | 3.7 | Below the observed aggregate attribution noise and located near fixed loop boundaries. There is no meaningful direct evidence of a variable exponentiation loop. |

## Disassembly evidence

The dominant `FixedUInt::shr` implementation is a constant-time barrel
shifter. Its outer loop runs all 32 `usize` bit positions, and its final limb
selection runs 16 limbs at every layer. Branches at `0x0800038a` and
`0x0800041a` consequently have a fixed per-invocation relationship. Their
compact statistics do not retain that relationship, proving that the address
counters cannot be interpreted as exact loop execution totals.

`subtle::black_box` at `0x0800265c` contains only:

```text
push; add; strb; ldrb; pop
```

Nevertheless, key A reported totals of 274/415/168 at its three nonzero
addresses while key B reported approximately 247/348/213. A real execution
cannot enter, execute, and return from this block in those proportions.

By contrast, the arithmetic does contain data-dependent predication that is
normally accepted as constant-time on Cortex-M. Examples include:

- `wrapping_sub`: `it lo; movlo` for borrow propagation.
- CIOS final subtraction: `it lo; movlo` for borrow propagation.
- `wide_mul`: predicated stores and carry materialization.

These instructions do not change ordinary branch flow, and skipped versus
executed predicate slots can retain equal cycle cost, but ETM can encode the
predicate outcome. That provides a credible explanation for an ETM event
signature difference with bit-for-bit identical DWT timing.

## Security interpretation

- **Aggregate timing:** no leak was observed in this campaign.
- **Ordinary secret-dependent branches or early exits:** not demonstrated by
  this profile.
- **Predicated instruction outcomes:** likely key-dependent and ETM-visible;
  expected for branchless carry and select idioms on Thumb.
- **Data-memory addresses:** not measured by these compact statistics.
- **Power and electromagnetic leakage:** not measured and cannot be inferred
  from this result.

The gate remains useful as a strict ETM trace-invariance regression gate, but
its failure criterion is stronger than conventional constant-time timing and
branch discipline. Future localization should use focused start/stop regions
around one primitive or a lossless branch/atom sequence instead of assigning
security meaning to the compact per-address histogram.

## Reproduction

Build the identical RSA-512 ETM fixture:

```sh
cargo build --manifest-path ct-verify/Cargo.toml \
  -p rsa-cyccnt-hardware --target thumbv7em-none-eabihf --release \
  --no-default-features \
  --features rsa512,carrier-u32x16,clock-168mhz,etm-single-trial
```

Run the hardware gate from the `embedded-measure` checkout:

```sh
cargo run --features cli --bin cargo-embedded-measure -- \
  jtrace-ct-gate \
  ../rsa/ct-verify/target/thumbv7em-none-eabihf/release/rsa-cyccnt-hardware \
  --output-dir ../rsa/ct-verify/target/embedded-measure/rsa512-etm-ct-gate \
  --probe-serial 001224000224 \
  --keys 2 --repetitions 3 \
  --max-dwt-spread 128 --max-profile-delta 128 \
  --rtt-probe-selector 1366:1020:001224000224 \
  --rtt-chip STM32F407VGTx
```

An exit status of 1 is the expected result for the documented profile
non-invariance.
