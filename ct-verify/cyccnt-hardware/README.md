# RSA signing CYCCNT fixtures

Compares whole blinded PKCS#1 v1.5 SHA-256 signing for two independent real
keypairs at each selected width on the J-Trace STM32F407VG. The gated measured
region is the signing API boundary: encoding, deterministic random blinding,
private exponentiation, constant-time inversion and unblinding,
verify-after-sign, and serialization. Public modulus parsing and Montgomery
parameter construction are performed before the gated region and emitted as a
separate diagnostic; the RSA secrecy contract treats the modulus as public.

Both keys start from the same deterministic RNG seed. A preflight call asserts
that they consume the same number of RNG words, so the recorded comparison
uses matched streams rather than merely matched initial state. Trials use RTT,
interrupt-free DWT `CYCCNT`, two exact-path balanced warm-up blocks, and
balanced ABBA/BAAB recorded order.

The carrier uses `krabi-caliper::PairedSuite` for DWT sampling, exact-path
warmups, matched-input comparison, safe counter-region enforcement, versioned
reporting, diagnostics, and totals. It emits lossless `EM_*` schema 1 records
plus legacy `CT_*` records during host tooling migration.

The default clock profile uses the internal 16 MHz HSI as the PLL source and
runs the core/HCLK at 168 MHz, with APB1 at 42 MHz and APB2 at 84 MHz. This
does not depend on a board-specific external crystal. Every run reports the
configured HCLK over RTT.

Run the complete 168 MHz declarative campaign:

```sh
cargo krabi-caliper run rsa-signing-ct-jtrace-f407
```

Use repeatable `--case` options to select `rsa512-u32x16`, `rsa512-u8x64`,
`rsa1024-u32x32`, or `rsa2048-u32x64`. The runner cross-compiles each exact
feature set, downloads and resets the target, releases the probe for the
width-qualified delay, and then attaches only to drain the blocking RTT
channel. It retains the ELF, exact download/reset/attach commands, preparation
and RTT logs, parsed result, report, and reproducibility metadata below
`target/krabi-caliper/rsa-signing-ct-jtrace-f407/`.

Direct development runs remain available, for example:

```sh
cargo run --release --features rsa1024,carrier-u32x32
```

For a reset-clock comparison at 16 MHz, disable the default clock feature:

```sh
cargo run --release --no-default-features --features rsa512,carrier-u32x16
cargo run --release --no-default-features --features rsa512,carrier-u8x64
cargo run --release --no-default-features --features rsa1024,carrier-u32x32
cargo run --release --no-default-features --features rsa2048,carrier-u32x64
```

The declarative runner automates the following detached sequence because live
RTT polling can starve debug access during long measured regions:

```sh
probe-rs download --chip STM32F407VGTx --protocol swd \
  --probe "$KRABI_PROBE" \
  ../target/thumbv7em-none-eabihf/release/rsa-cyccnt-hardware
probe-rs reset --chip STM32F407VGTx --protocol swd \
  --probe "$KRABI_PROBE"
# Wait for the width/clock-qualified campaign duration, then drain evidence.
probe-rs attach --chip STM32F407VGTx --protocol swd \
  --probe "$KRABI_PROBE" \
  ../target/thumbv7em-none-eabihf/release/rsa-cyccnt-hardware
```

The blocking 4 KiB RTT channel preserves records until attachment. Do not
replace the declarative detached profile with `probe-rs run` for the full
campaign; attaching during the measured region recreates the debug-bus
contention this sequence avoids.

## Bounded ETM constant-time gate

The detailed verdict and address-family classification are recorded in
[`ETM_PROFILE_FINDINGS.md`](ETM_PROFILE_FINDINGS.md).

The `etm-single-trial` feature turns this same signing boundary into a
host-selected, one-operation ETM fixture. Both keys remain in one identical
ELF. While the reset core is halted, `cargo krabi-caliper
jtrace-ct-gate` writes the key index into the exported uninitialized selector,
arms DWT comparators as ETM start/stop events, and runs until a terminal
`BKPT` outside the measured region. The target then exposes the observed key,
signing validity, RNG draw count, and its DWT cycle delta for host validation.

Build RSA-512 explicitly from the nested workspace root:

```sh
cargo build --manifest-path ct-verify/Cargo.toml \
  -p rsa-cyccnt-hardware --target thumbv7em-none-eabihf --release \
  --no-default-features \
  --features rsa512,carrier-u32x16,clock-168mhz,etm-single-trial
```

On 2026-07-18, a two-key, three-repetition J-Trace run produced a valid
hardware **FAIL**: same-key compact ETM profiles stayed within the calibrated
128-count allowance (maximum distance 92), but cross-key distance reached
1,827. All six operations succeeded and consumed 40 RNG words. In contrast,
every target DWT measurement was exactly 142,389,660 cycles. The first DWT
value was read directly from target memory and independently recovered from
the RTT `ETM_TRIAL` record with an exact match.

This finding means aggregate cycle equality did not imply an equivalent ETM
execution-address profile. It does not by itself prove an exploitable timing
leak: SEGGER's compact counters have observable repeat-run attribution jitter,
and they do not expose data-memory addresses. The retained symbolized diff is
the starting point for reviewing the key-dependent profile in fixed-bigint,
modular exponentiation, and signing code. Generated evidence lives under
`target/krabi-caliper/rsa512-etm-ct-gate-final/` and is intentionally not
committed.

Initial 16 MHz STM32F407/J-Trace calibration passed both fixtures on both
carriers:

- `u32x16`: signing took approximately 141.2 million cycles with 16 cycles
  combined spread.
- `u8x64`: signing took approximately 558.8 million cycles with 14 cycles
  combined spread.
- Both keypairs consumed exactly 40 RNG words from the matched stream.
- The early-exit negative control separated by 509 cycles.

Public key construction differed by 40,160 cycles (`u32x16`) and 142,773
cycles (`u8x64`), reported diagnostically rather than gated because the modulus
is public under RSA's documented secrecy contract.

The 168 MHz HSI/PLL calibration also passed both fixtures:

- `u32x16`: 142,693,252–142,693,253 cycles, 1-cycle combined spread,
  approximately 1.177 signing operations per second.
- `u8x64`: 559,621,229–559,621,230 cycles, 1-cycle combined spread,
  approximately 0.3002 signing operations per second.
- Both carriers again consumed 40 RNG words and passed the early-exit negative
  control.

The operations-per-second figures are `hclk_hz / cycles`; they are qualified
for the reported 168 MHz profile and are not inferred from cycles alone.

The 168 MHz RSA-1024 `u32x32` campaign also passed:

- Signing took 535,722,162–535,722,164 cycles, a 2-cycle combined spread.
- Both independent keypairs consumed exactly 48 RNG words from matched streams.
- Throughput was approximately 0.3136 signing operations per second.
- The early-exit negative control separated by 1,069 cycles.
- The measured signing region used only 12.5% of the 32-bit DWT interval.

RSA-1024 took 3.75 times the cycles of RSA-512 on the corresponding `u32`
backend. A simple quadratic-width projection puts RSA-2048 near 2.14 billion
cycles, leaving about 50% DWT headroom; that projection is planning evidence,
not a substitute for measuring RSA-2048 directly.

The 168 MHz RSA-2048 `u32x64` campaign passed without counter wrapping or
phase splitting:

- Signing took 2,150,109,165–2,150,109,167 cycles, a 2-cycle combined spread.
- Both independent keypairs consumed exactly 64 RNG words from matched streams.
- Throughput was approximately 0.07814 signing operations per second, or
  12.798 seconds per operation.
- The early-exit negative control separated by 2,134 cycles.
- Peak stack high-water measurement was 33,316 bytes.
- The measured signing region used 50.06% of the 32-bit DWT interval and
  53.40% of the fixture's conservative `0xf000_0000` limit.

RSA-2048 took 4.013 times the RSA-1024 cycle count, closely matching the
quadratic-width projection. The release image contains 23,476 bytes of text
and 1,092 bytes of static RAM on the 512 KiB flash / 128 KiB RAM target.
