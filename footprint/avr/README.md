# AVR footprint campaign

Install the shared host tool, then run either the full or CI-sized campaign.
`krabi-caliper` isn't published on crates.io yet, so install it from the pinned
git tag (the same revision the workspace `[patch.crates-io]` points at):

```sh
cargo install --git https://github.com/kaidokert/krabi-caliper-rs \
  --tag v0.1.0-alpha.2 krabi-caliper --features cli
cargo krabi-caliper run rsa-avr
cargo krabi-caliper run rsa-avr-fast
```

For local toolkit development, install with
`cargo install --path ../../../krabi-caliper --features cli --force`.
The campaign builds with the consumer-owned `nightly-2025-11-01` pin and
retains ELF, protocol, stack, timing, and baseline-delta reports below
`target/krabi-caliper/`.
