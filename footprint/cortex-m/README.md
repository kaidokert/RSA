# Cortex-M footprint harness

The shared Rust runner owns the QEMU M0/M3/M4 matrix, semihosting capture,
ELF accounting, deadlines, baseline deltas, and reports. Run
`cargo embedded-measure run rsa-cortex-m0` (or the `m3`/`m4` campaign) in this
directory; configuration lives in `embedded-measure.toml`.

The same case set runs on the J-Trace reference board through the declarative
`probe-rs` profile. For a focused RSA-512 run:

```sh
cargo embedded-measure run rsa-jtrace-f407 \
  --case baseline --case rsa512-sha1-u32
```

The equivalent direct command remains useful when diagnosing probe failures:

```sh
cargo build --release --target thumbv7em-none-eabihf \
  --example rsa_verify \
  --features jtrace-f407,key_512,limb_u32,hash_sha256
probe-rs run --chip STM32F407VGTx --protocol swd \
  --probe 1366:1020:001224000224 \
  target/thumbv7em-none-eabihf/release/examples/rsa_verify
```

Hardware metrics include the stack high-water mark, raw DWT `CYCCNT` as
`dwt_cycles`, and raw `systick_cycles`. The legacy `cycles` field remains
SysTick cycles divided by 1,000 for QEMU compatibility. DWT measurements must
be shorter than 2^32 core cycles. Stack painting and scanning use the shared
`embedded-measure` probe also used by the RISC-V and AVR harnesses.
Stack results are emitted as versioned `EM_STACK` records; the legacy
`METRIC stack:` field remains during parser migration.
