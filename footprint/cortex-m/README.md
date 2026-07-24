# Cortex-M footprint harness

The shared Rust runner owns the QEMU M0/M3/M4 matrix, semihosting capture,
ELF accounting, deadlines, baseline deltas, and reports. Run
`cargo krabi-caliper run rsa-cortex-m0` (or the `m3`/`m4` campaign) in this
directory; configuration lives in `krabi-caliper.toml`.

The same case set runs on the J-Trace reference board through the declarative
`probe-rs` profile. For a focused RSA-512 run:

```sh
cargo krabi-caliper run rsa-jtrace-f407 \
  --case baseline --case rsa512-sha1-u32
```

The equivalent direct command remains useful when diagnosing probe failures:

```sh
cargo build --release --target thumbv7em-none-eabihf \
  --example rsa_verify \
  --features jtrace-f407,key_512,limb_u32,hash_sha1
probe-rs run --chip STM32F407VGTx --protocol swd \
  --probe 1366:1020:001224000224 \
  target/thumbv7em-none-eabihf/release/examples/rsa_verify
```

Hardware evidence uses canonical `EM_MEASUREMENT` records with `systick` and
`dwt` counter names, plus a versioned `EM_STACK` record. DWT measurements must
be shorter than 2^32 core cycles. Stack painting, counter acquisition, and
reporting use the same `krabi-caliper` lifecycle adapter as the QEMU fixtures.
