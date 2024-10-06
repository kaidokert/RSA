# RustCrypto: RSA (No-Heap Fork)

This repo is a fork of the [RustCrypto RSA crate](https://crates.io/crates/rsa)

## What's Different?

This fork is a **proof of concept** focused on **removing heap usage** and **allocations**. It's written for environments where memory constraints are tight, such as **embedded systems** or **no_std** contexts.

### Key Features

- **No heap allocations**: All operations run entirely on the stack.
- **Public Key Functions**: Only public key operations like **signature verification** and **encryption** are implemented so far.
- **Pluggable BigInt**: The `BigInt` implementation is swappable. It’s a type parameter in the `RsaPublicKey<T>`, where `T` must implement `num_traits::PrimInt` and some additional traits.

### What's Missing?

- **Private Key Operations**: Private key functions (like signing and decryption) are stubbed out.
- **A lot of tests**: Most of the tests from original are stubbed out, as they rely on PEM key decoding functions that need heap.
- **No expectation of security**: Only signature verification is probably okay to use.

## Why This Fork?

It's a proof of concept to try how compact a RSA implementation can become. Currently tested on Cortex-M0, fitting into about 8Kb code space and requiring about 3kB stack at the minimum.
