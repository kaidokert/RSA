# RISC-V footprint harness

Run the complete SiFive-E QEMU matrix with:

```sh
cargo embedded-measure run rsa-riscv32
```

The firmware emits the shared `EM_*` protocol over UART. The Rust runner stops
the non-exiting machine after `EM_OUTCOME`, retains each ELF, and reports
verification-minus-baseline flash, stack, and cycle deltas.
