# RSA signing CYCCNT fixtures

Compares whole blinded PKCS#1 v1.5 SHA-256 signing for two independent real
keypairs at each selected width on the J-Trace STM32F407VG (the 768-bit gate
adds a PSS fixture over the same private op). The gated measured
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
alongside legacy `CT_*` records for host-tooling compatibility.

The default clock profile uses the internal 16 MHz HSI as the PLL source and
runs the core/HCLK at 168 MHz, with APB1 at 42 MHz and APB2 at 84 MHz. This
does not depend on a board-specific external crystal. Every run reports the
configured HCLK over RTT.

## Continuous gate: two clocks (`hw-ct`)

At 168 MHz the F407 runs 5 flash wait states, so the ART prefetch/I-cache adds
secret-independent fetch jitter that scales with operation length and swamps a
tight cycle gate. 30 MHz is the F407's 0-wait-state ceiling: no ART, so DWT core
cycles are deterministic. The CI gate therefore splits across both clocks:

- **`rsa768-ct-jtrace-f407-30mhz`** — the CT gate proper, at 30 MHz / 0 WS.
  768-bit (`carrier-u32x24`) is the smallest OAEP-SHA256-compatible width, so the
  gate exercises a realistic key. The deterministic (near-zero-variance)
  measurement makes a small sample count valid; the CT property itself is
  width-independent (fixed-iteration ladder / safegcd), proven at this width.
  Two `positive` fixtures run here — `pkcs1v15_blinded_sign` and
  `pss_blinded_sign`. Both route through the same blinded private op (the whole
  secret-dependent surface); PSS additionally covers the distinct EMSA-PSS
  encoding path (MGF1 + salt), and 768 is the smallest width where PSS's
  `emLen >= hLen + sLen + 2` fits.
- **`rsa2048-smoke-jtrace-f407-168mhz`** — a deployment-width functional smoke
  (`gate = false`) confirming a 2048-bit key signs correctly on hardware; 168 MHz
  keeps its wall time bounded (a 2048 sign at 30 MHz would run minutes).

Measured wall time on the reference bench is ~15 min (768 gate ~7.5 min: build +
two 4-sample positive fixtures at ~13s/sign at 30 MHz; 2048 smoke ~7 min: build +
one 4-sample fixture at ~50s/sign at 168 MHz), plus rig queue/flash overhead.

Per-sample lifecycle conditioning (`positive_conditioned`) is available behind
the off-by-default `conditioning` feature; at 0 WS it is belt-and-suspenders, and
enabling it doubles the sign count, so the gate builds run without it.

The all-width 168 MHz survey below is a manual diagnostic, not the CI gate.

Run the complete 168 MHz declarative survey:

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
