# Cortex-M footprint harness

`run_suite.py` retains the QEMU M0/M3/M4 matrix and semihosting transport.

The measured RSA examples also run on the J-Trace reference board's
STM32F407VG using RTT:

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
