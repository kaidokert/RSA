# Constant-time verification harness

Machine-checked evidence for the heapless sign path's constant-time and
panic-free claims. Four layers, each answering a question the others
can't, all pinned to one toolchain and one release profile so a passing
run "locks" specific machine code rather than an optimizer's mood.

This is a nested cargo workspace, excluded from the published crate.
The pinned profile (`lto = "fat"`, `codegen-units = 1`,
`opt-level = "z"`, `panic = "abort"`) lives in [`Cargo.toml`](Cargo.toml)
and matches what a size-conscious embedded deployment builds; CI pins
rustc 1.87.0 (the crate MSRV) so codegen drift surfaces as a reviewable
diff, not silent rot.

## What is attested

Every fixture drives the **whole blinded PKCS#1 v1.5 sign** through the
public deployment API (`GenericSigningKey::try_sign_with_rng_into` /
`try_sign_prehash_with_rng_into`): padding, random-mod blinding-factor
sampling, the blinded `c^d` exponentiation, `InvertCt`/`MulCt`
unblinding, verify-after-sign, and signature serialization. The gates
verify *fixture instantiations, not generic code*, so the matrix covers
every shipped carrier flavor at the width we actually deploy:

| fixture suffix | modulus | limbs | deployment shape |
| -------------- | ------: | ----- | ---------------- |
| `fb8__N64`     |     512 | `u8`  | fast PR-gate shape |
| `fb32__N64`    |    2048 | `u32` | Cortex-M / RISC-V |
| `fb8__N256`    |    2048 | `u8`  | AVR-class |
| `fb64__N32`    |    2048 | `u64` | 64-bit hosts |

Keys are real generated keypairs (`e = 65537`), shared between the
fixture crates via [`test_keys.rs`](test_keys.rs), so the happy path
(including verify-after-sign) is the code under inspection rather than
a retry-then-fail path.

## The four layers

All run commands below assume this directory (`ct-verify/`) as the
working directory.

**Layer 0 — typestate compile gates** (in `src/traits/modular.rs`
tests, not this workspace). `static_assertions` pins that only
`Ct`-personality modulus parameters implement `CtModulusParams`; an
`Nct`-personality key fails the encrypt/sign bounds at compile time.

**Ladder branch-freedom check** ([`ct-driver`](ct-driver/)). Cross-builds
the fixture staticlib per ISA (thumbv7em/7m/6m, riscv32imc/imac),
disassembles it, and asserts each `Field::<Ct>::exp` monomorphization —
the secret-exponent ladder — carries at most the reviewed public
bit-width loop-guard branch count (1 on Thumb, 2 on RV32) and nothing
more. Fails closed: it requires exactly one ladder monomorphization per
positive fixture in the archive (a missing one means a carrier's ladder
was inlined/renamed and its attestation would be vacuous), and the
negative controls must trip the per-ISA mnemonic tables. Deliberately
narrow — a whole RSA sign is full of legitimate branches on public
data, so asm-grep at whole-operation granularity produces only false
positives; secret-vs-public discrimination belongs to the next layer.

```sh
cargo run --release -p ct-driver -- --target thumbv7m-none-eabi
```

**Taint (ctgrind) — the primary whole-operation gate**
([`ct-ctgrind`](ct-ctgrind/)). The secret exponent's bytes are marked
undefined via crabgrind (`MAKE_MEM_UNDEFINED`); Valgrind memcheck then
flags any conditional jump or memory access that depends on them,
through every inlined dependency, across the entire sign. Runs on
x86_64 and aarch64 (Linux; use the [Dockerfile](ct-ctgrind/Dockerfile)
on macOS). Negative controls — a secret-dependent early-exit loop and a
vartime compare — must trip, proving the harness has teeth.

```sh
# On x86_64, build with the same CPU baseline CI attests:
#   export RUSTFLAGS="-C target-feature=+lzcnt,+bmi1"
cargo build --release -p ct-ctgrind
valgrind --tool=memcheck --error-limit=no --error-exitcode=0 \
  --suppressions=ct-ctgrind/ct-ctgrind.supp -q target/release/ct-ctgrind
```

Suppressions ([`ct-ctgrind.supp`](ct-ctgrind/ct-ctgrind.supp)) are
individually reviewed declassifications, not blanket: data-oblivious
`memcpy` shadow-propagation artifacts, and the leading-zero trim of the
signature — secret-*derived* but public-by-design (it is what the
caller publishes). Every entry requires a sign-fixture frame, and every
CT-critical primitive is a separate symbol never matched by any entry,
so a real leak in the crypto path always surfaces.

**Panic-free audit** ([`panic-free-audit`](panic-free-audit/)).
Cross-builds the whole sign as a DCE'd staticlib and asserts via
`llvm-nm` that no `core::panicking` machinery was linked. For a signer,
a reachable panic is both a DoS edge and a timing oracle (the
panic-formatting path's cost depends on the values formatted). The
prehash sign variant keeps `sha2` compression out of the archive,
scoping the audit to this crate's composition.

```sh
sh panic-free-audit/check.sh thumbv7m-none-eabi
```

This layer has caught real bugs at real deployment widths twice
(fixed-bigint 0.5.0's `holder_be` slice indexing; 0.5.1's
`copy_from_slice` length proof failing on rustc 1.87 for some limb
counts). **Consumers who want the no-panic property must use
fixed-bigint ≥ 0.5.2**, where the byte serialization is structurally
panic-free rather than dependent on the optimizer proving bounds.

## Violation triage policy

When a layer goes red, where the finding lives decides what happens:

1. **Fork-owned code** (fork-added functions, fork-only files): fix
   here, with fallible slicing / byte-loop idioms that convert
   would-be panics into the existing error returns.
2. **Upstream-shared lines** (code inherited from RustCrypto/RSA):
   do not fix here — upstream-diff minimization is a binding
   constraint. Flag it, defer upstream.
3. **A dependency** (fixed-bigint, modmath): fix in that crate,
   release, bump the minimum here. Exercised twice (fixed-bigint
   0.5.1, 0.5.2).

## Honest gaps

- **Branchless selects on secrets are invisible to taint.** memcheck
  flags conditional *jumps* and addresses, not `csel`/`cmov` data
  flow. The ladder layer partially compensates by counting every
  conditional branch in the exponentiation; a secret-dependent select
  elsewhere would evade both. This is inherent to the tool class until
  symbolic-execution tooling (cargo-checkct / binsec) is adopted.
- **Taint runs on host ISAs** (x86_64, aarch64), not on the Thumb or
  RV32 encodings that deploy. The ladder check covers those encodings
  for the exponentiation only; Thumb IT-block predication elsewhere is
  counted by the mnemonic tables but not taint-checked on target.
- **x86_64 taint is verified at the CI CPU baseline**
  (`+lzcnt,+bmi1`); other feature levels could emit different code.
- **Cache-timing and speculative side channels are out of scope** —
  no tool in this harness observes them.
- **Suppressions encode reviewed judgment**, not proof, about what is
  public-by-design. The review rationale is inline in the `.supp`.
- **Scope is this crate's code at whole-operation level.** The
  upstream primitives (modmath's CIOS/safegcd/exp, fixed-bigint's
  arithmetic) are attested by their own harnesses — the same layer
  stack this one mirrors — and are covered here only transitively,
  as inlined into our call chains at our widths. The alloc backend
  (`BoxedUint`) is upstream RustCrypto's concern and gets no fixtures.
