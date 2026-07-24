# AVR footprint campaign

Install the shared host tool, then run either the full or CI-sized campaign:

```sh
cargo install krabi-caliper --version 0.1.0 --features cli,campaign
cargo krabi-caliper run rsa-avr
cargo krabi-caliper run rsa-avr-fast
```

For local toolkit development, install with
`cargo install --path ../../../krabi-caliper --features cli --force`.
The campaign builds with the consumer-owned `nightly-2025-11-01` pin and
retains ELF, protocol, stack, timing, and baseline-delta reports below
`target/krabi-caliper/`.
