### rsa heapless fork

[![CI](https://github.com/kaidokert/RSA/actions/workflows/ci.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/ci.yml)
[![AVR](https://github.com/kaidokert/RSA/actions/workflows/avr.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/avr.yml)
[![Cortex-M](https://github.com/kaidokert/RSA/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/cortex_m.yml)
[![RISC-V](https://github.com/kaidokert/RSA/actions/workflows/riscv.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/riscv.yml)

A microcontroller-friendly fork of the [RustCrypto RSA crate](https://github.com/RustCrypto/RSA). Public-key operations — PKCS#1 v1.5 verify, OAEP encrypt, PSS verify — are generic over the bigint backend, with a no-alloc path through [fixed-bigint](https://crates.io/crates/fixed-bigint) and [modmath](https://crates.io/crates/modmath) tested on 8-bit AVR, Cortex-M and RISC-V.

#### Scope

This is a proof of concept focused on shrinking code size and stack usage. Public-key only — verification and encryption — which covers the common embedded use cases (bootloader signature checks, key wrapping to a server).

Private-key operations (key generation, signing, decryption) are deliberately omitted from the heapless path on safety grounds: doing them correctly requires constant-time primitives, a trustworthy RNG, and secure key storage that the dependency stack doesn't yet provide. The full upstream behavior remains available via the `alloc` and `private-key` feature flags on a heap-allocating backend; license, MSRV, and security advisories there follow the upstream crate, preserved verbatim in [`UPSTREAM_README.md`](UPSTREAM_README.md).

#### Resource usage (as of version 0.10.0-rc.18)

PSS signature verification. The `u8` backend uses 8-bit limbs (more portable, works on 8-bit AVR); the `u32` backend uses 32-bit limbs (natural on 32-bit cores). Full sweeps across key sizes, operations, and targets live under [`footprint/`](footprint/).

| Target          |  Key | Hash    | Backend | .text (KiB) | Stack (bytes) |
| --------------- | ---: | ------- | ------- | ----------: | ------------: |
| ATmega2560      |  512 | SHA-1   | u8      |        27.2 |          2198 |
| Cortex-M0       |  512 | SHA-1   | u32     |         8.9 |          3760 |
| Cortex-M0       | 2048 | SHA-256 | u32     |        15.6 |          9256 |
| Cortex-M3       |  512 | SHA-1   | u32     |         9.2 |          3776 |
| Cortex-M3       | 2048 | SHA-256 | u32     |        13.0 |          9144 |
| sifive_e (RV32) |  512 | SHA-1   | u32     |        11.1 |          2036 |
| sifive_e (RV32) | 2048 | SHA-256 | u32     |        21.2 |          8436 |

#### Example (host, alloc)

```rust
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
let pub_key: RsaPublicKey = /* parse from DER/PEM via pkcs1/pkcs8 */;
let enc = pub_key.encrypt(&mut rand::rng(), Pkcs1v15Encrypt, b"hello").unwrap();
```

For no-alloc usage (embedded), see the [`examples/`](examples/) and [`footprint/`](footprint/) directories.
