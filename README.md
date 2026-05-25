### rsa heapless fork

[![CI](https://github.com/kaidokert/RSA/actions/workflows/ci.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/ci.yml)
[![AVR](https://github.com/kaidokert/RSA/actions/workflows/avr.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/avr.yml)
[![Cortex-M](https://github.com/kaidokert/RSA/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/cortex_m.yml)
[![RISC-V](https://github.com/kaidokert/RSA/actions/workflows/riscv.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/riscv.yml)

A microcontroller-friendly fork of the [RustCrypto RSA crate](https://github.com/RustCrypto/RSA). Public-key operations — PKCS#1 v1.5 verify, OAEP encrypt, PSS verify — are generic over the bigint backend, with a no-alloc path through [fixed-bigint](https://crates.io/crates/fixed-bigint) and [modmath](https://crates.io/crates/modmath) tested on 8-bit AVR, Cortex-M and RISC-V.

#### Scope

This is a proof of concept focused on shrinking code size and stack usage. Public-key only — verification and encryption — which covers the common embedded use cases (bootloader signature checks, key wrapping to a server). Private-key operations (key generation, signing, decryption) are out of scope on the heapless path: they need constant-time primitives, a trustworthy RNG, and secure key storage that the dependency stack doesn't yet provide. The full upstream behavior remains available via the `alloc` and `private-key` feature flags on a heap-allocating backend.

#### Resource usage (as of version 0.10.0-rc.18)

| Target | Key | Operation | Backend | .text (KiB) | Stack (bytes) |
| ------ | --- | --------- | ------- | ----------: | ------------: |
| AVR ATmega2560 | RSA-2048 | PSS verify (SHA-256) | u8×256 |   |   |
| Cortex-M0      | RSA-2048 | PSS verify (SHA-256) | u8×256 |   |   |
| Cortex-M3      | RSA-2048 | PSS verify (SHA-256) | u8×256 |   |   |
| RV32IMAC       | RSA-2048 | PSS verify (SHA-256) | u32×64 |   |   |

#### Example (host, alloc)

```rust
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
let pub_key: RsaPublicKey = /* parse from DER/PEM via pkcs1/pkcs8 */;
let enc = pub_key.encrypt(&mut rand::rng(), Pkcs1v15Encrypt, b"hello").unwrap();
```

For no-alloc usage (embedded), see the [`examples/`](examples/) and [`footprint/`](footprint/) directories.
