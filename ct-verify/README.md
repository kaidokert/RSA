# Constant-time verification harness

Checks for the heapless sign path's constant-time and panic-free claims.
There are five layers. Each checks something the others cannot.

This is a nested cargo workspace, excluded from the published crate. Its
release profile in [`Cargo.toml`](Cargo.toml) is `lto = "fat"`,
`codegen-units = 1`, `opt-level = "z"`, `panic = "abort"`, which is what
a size-conscious embedded build uses. CI pins the toolchain too, so a
codegen change shows up as a failing or changed gate rather than going
unnoticed.

Cargo ignores a dependency's `[profile]`, so a deployment picks its own
opt-level. CI runs the ladder check, the panic audit, the taint gate and
the hardware campaigns at both `"z"` and `"s"` by setting
`CARGO_PROFILE_RELEASE_OPT_LEVEL`. Set the same variable to reproduce a
run locally.

## What the fixtures cover

Every fixture runs the whole blinded PKCS#1 v1.5 sign through the public
API (`GenericSigningKey::try_sign_with_rng_into` /
`try_sign_prehash_with_rng_into`): padding, sampling the blinding
factor, the blinded `c^d` exponentiation, unblinding with
`InvertCt`/`MulCt`, verify-after-sign, and serializing the signature.
The gates check concrete instantiations, not generic code, so there is
one fixture per carrier at the width it ships at:

| fixture suffix | modulus | limbs | used for |
| -------------- | ------: | ----- | -------- |
| `fb8__N64`     |     512 | `u8`  | fast PR gate |
| `fb32__N64`    |    2048 | `u32` | Cortex-M / RISC-V |
| `fb8__N256`    |    2048 | `u8`  | AVR-class |
| `fb64__N32`    |    2048 | `u64` | 64-bit hosts |

The keys are real generated keypairs (`e = 65537`) shared through
[`test_keys.rs`](../tests/fixtures/test_keys.rs), so the code under test
is the successful path, verify-after-sign included, not a retry or error
path.

## Layers

The commands below run from this directory (`ct-verify/`).

**Typestate compile gates** (tests in `src/traits/modular.rs`, outside
this workspace). `static_assertions` checks that only `Ct` modulus
parameters implement `CtModulusParams`, so a key with `Nct` parameters
does not satisfy the encrypt and sign bounds.

**Ladder branch check** ([`ct-driver`](ct-driver/)). Cross-builds the
fixture staticlib for thumbv7em, thumbv7m, thumbv6m, riscv32imc and
riscv32imac, disassembles it, and checks each `Field::<Ct>::exp`
instance, the secret-exponent ladder. Each may contain at most one
conditional branch, the loop over the exponent's public bit width.

Loops over public bounds are accepted by shape. At `"s"` the per-limb
select loops are inlined into the ladder, and krabi-caliper's
counted-loop model recognises their constant-step counters. The model
cannot tell where a loop bound came from, so the negative controls are
loops that exit early on a loaded byte, and they must still be reported.

The check fails if any positive fixture lacks its ladder symbol, because
a ladder that was inlined or renamed would otherwise pass unchecked. It
also fails if a negative control is not reported. It looks only at the
ladder: a whole RSA sign has many legitimate branches on public data, so
telling secret from public branches is left to the taint gate.

```sh
cargo run --release -p ct-driver -- --target thumbv7m-none-eabi
```

**Taint gate** ([`ct-ctgrind`](ct-ctgrind/)). This is the main check
over the whole operation. krabi-caliper marks the secret exponent's
bytes undefined (`MAKE_MEM_UNDEFINED`, through crabgrind), and Valgrind
memcheck reports any conditional jump or memory address that depends on
them, anywhere in the sign, inlined code included. It runs on x86_64 and
aarch64 Linux; on macOS use the [Dockerfile](ct-ctgrind/Dockerfile).
Five negative controls must be reported: krabi-caliper's standard
branch, equality and index controls, an early-exit loop on a secret, and
a variable-time compare.

```sh
# On x86_64, use the CPU baseline CI uses:
#   export RUSTFLAGS="-C target-feature=+lzcnt,+bmi1"
cargo build --release -p ct-ctgrind
cargo krabi-caliper ctgrind target/release/ct-ctgrind \
  --valgrind-arg=--suppressions=ct-ctgrind/ct-ctgrind.supp
```

Each entry in [`ct-ctgrind.supp`](ct-ctgrind/ct-ctgrind.supp) has been
reviewed. They cover two things:
- Valgrind's imprecise tracking through `memcpy`, which does not branch
  on the bytes it copies.
- The leading-zero trim when the signature is serialized. The signature
  is computed from the secret but is public by design.

Fat LTO inlines most of the crypto path into the fixture. So every entry
names the routine it covers as the innermost frame, and none matches on
the fixture frame alone.

One more value is public by design: the result of the verify-after-sign
comparison. It is declassified in the library rather than suppressed.
The private op passes it to `ct_probe::declassify` (feature
`ct-declassify`, enabled only by this harness), and the harness untaints
that value alone.

**Panic-free audit** ([`panic-free-audit`](panic-free-audit/)).
Cross-builds the whole sign as a staticlib with unused code removed and
checks with `llvm-nm` that no `core::panicking` code was linked. In a
signer, a reachable panic is a denial-of-service path, and also a timing
signal, since formatting the panic message takes time that depends on
the values printed. The fixture signs a prehash, which keeps `sha2`
compression out of the archive and limits the audit to this crate's
code.

```sh
cargo krabi-caliper panic-audit --workspace . --package panic-free-audit \
  --target thumbv7m-none-eabi --features panic-handler \
  --negative-features neg-controls --owned-symbol '.*' \
  --expect-negative panic_audit__neg__bounds_check \
  --expect-negative panic_audit__neg__unwrap \
  --expect-negative panic_audit__neg__expect
```

**Hardware cycle counts** ([`cyccnt-hardware`](cyccnt-hardware/)).
Runs whole blinded signing with two independent real keypairs on a
J-Trace STM32F407VG and compares DWT cycle counts. The CI gate uses a
768-bit key at 30 MHz with 0 wait states. The two keys use matched
deterministic RNG streams, and their draw counts must agree. Building
the public key is reported separately; the measured region starts at the
signing call, because the modulus is public.

```sh
cd cyccnt-hardware
cargo run --release --features rsa512,carrier-u32x16
cargo run --release --features rsa512,carrier-u8x64
```

## When a layer fails

Where the finding is decides what happens:

1. **Code only in this fork:** fix it here, using fallible slicing or
   byte loops that turn a would-be panic into one of the existing
   errors.
2. **Code shared with RustCrypto/RSA:** don't fix it here, because the
   fork keeps its diff with upstream small. Record it and raise it
   upstream.
3. **A dependency** (fixed-bigint, modmath): fix it in that crate,
   release, and raise the minimum version here.

## Known gaps

- **Taint does not see branchless selects on secrets.** memcheck reports
  conditional jumps and addresses, not data flow through `csel`/`cmov`.
  The ladder check counts every conditional branch in the
  exponentiation, but a secret-dependent select elsewhere would pass
  both. Closing this needs symbolic-execution tooling such as
  cargo-checkct or binsec.
- **Taint runs on host ISAs** (x86_64, aarch64), not on the Thumb or
  RV32 code that ships. The ladder check covers those targets for the
  exponentiation only. Thumb IT-block predication elsewhere is counted
  by the mnemonic tables but not taint-checked on target.
- **x86_64 taint is checked at the CI CPU baseline** (`+lzcnt,+bmi1`).
  Other feature levels could produce different code.
- **Cache timing and speculative side channels are out of scope.** No
  tool here observes them.
- **Suppressions and declassifications are reviewed judgments**, not
  proofs, that a value is public. The reasoning for each is next to it,
  in the `.supp` file or at the `declassify` call.
- **Scope is this crate's code, over whole operations.** The upstream
  primitives (modmath's CIOS, safegcd and exponentiation, fixed-bigint's
  arithmetic) have their own harnesses with the same layers. Here they
  are covered only as inlined into this crate's code at these widths.
  The alloc backend (`BoxedUint`) belongs to upstream RustCrypto and has
  no fixtures.
