### rsa heapless fork

[![CI](https://github.com/kaidokert/RSA/actions/workflows/ci.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/ci.yml)
[![AVR](https://github.com/kaidokert/RSA/actions/workflows/avr.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/avr.yml)
[![Cortex-M](https://github.com/kaidokert/RSA/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/cortex_m.yml)
[![RISC-V](https://github.com/kaidokert/RSA/actions/workflows/riscv.yml/badge.svg)](https://github.com/kaidokert/RSA/actions/workflows/riscv.yml)

A microcontroller-friendly fork of the [RustCrypto RSA crate](https://github.com/RustCrypto/RSA). RSA operations — PKCS#1 v1.5 verify and sign, PSS verify and sign, OAEP encrypt — are generic over the bigint backend, with a no-alloc path through [fixed-bigint](https://crates.io/crates/fixed-bigint) and [modmath](https://crates.io/crates/modmath) tested on 8-bit AVR, Cortex-M and RISC-V.

#### Scope

Focused on shrinking code size and stack usage. The heapless path covers verify (PKCS#1 v1.5, PSS), OAEP encrypt, and sign (PKCS#1 v1.5, PSS) — constant-time in the private exponent, with optional per-signature blinding.

Key generation stays off the heapless path — it needs the heavy `crypto-primes` stack, and embedded keys arrive from a provisioning path (PEM/PKCS#8, HSM, firmware constants) rather than being generated on-device. It is available behind the `keygen` feature (on by default) on the heap-allocating backend. Decryption on the heapless path is out of scope. Full upstream behavior remains available via the `alloc` feature; license, MSRV, and security advisories there follow the upstream crate, preserved verbatim in [`UPSTREAM_README.md`](UPSTREAM_README.md).

Constant-time testing is documented in [`ct-verify/README.md`](ct-verify/README.md).

#### Resource usage (as of version 0.10.0-rc.18)

PSS signature verification. The `u8` backend uses 8-bit limbs (more portable, works on 8-bit AVR); the `u32` backend uses 32-bit limbs (natural on 32-bit cores). Full sweeps across key sizes, operations, and targets live under [`footprint/`](footprint/).

| Target          |  Key | Hash    | Backend | .text (KiB) | Stack (bytes) |
| --------------- | ---: | ------- | ------- | ----------: | ------------: |
| ATmega2560      |  512 | SHA-1   | u8      |        27.4 |          3099 |
| Cortex-M0       |  512 | SHA-1   | u32     |         8.9 |          4208 |
| Cortex-M0       | 2048 | SHA-256 | u32     |        15.5 |         11724 |
| Cortex-M3       |  512 | SHA-1   | u32     |         9.2 |          4216 |
| Cortex-M3       | 2048 | SHA-256 | u32     |        13.1 |         11564 |
| sifive_e (RV32) |  512 | SHA-1   | u32     |        11.3 |          2840 |
| sifive_e (RV32) | 2048 | SHA-256 | u32     |        21.1 |         11736 |

#### Example (host, alloc)

```rust,ignore
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
let pub_key: RsaPublicKey = /* parse from DER/PEM via pkcs1/pkcs8 */;
let mut rng = rand::rng();
let enc = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, b"hello").unwrap();
```

For no-alloc usage (embedded), see the [`examples/`](examples/) and [`footprint/`](footprint/) directories.
