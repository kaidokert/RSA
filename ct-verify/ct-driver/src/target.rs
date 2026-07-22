//! Per-target specifications: triple, toolchain pin, and the mnemonic
//! tables used by the parser.

use krabi_caliper::host::ct_asm::LadderTarget as TargetSpec;
use krabi_caliper::host::isa as mnemonics;

/// All targets we know how to verify, in priority order.
pub const TARGETS: &[TargetSpec] = &[
    // Priority 1: Cortex-M3/M4
    TargetSpec {
        triple: "thumbv7em-none-eabi",
        priority: 1,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "thumbv7m-none-eabi",
        priority: 1,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    // Priority 2: Cortex-M0
    TargetSpec {
        triple: "thumbv6m-none-eabi",
        priority: 2,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    // Priority 3: 32-bit RISC-V
    TargetSpec {
        triple: "riscv32imc-unknown-none-elf",
        priority: 3,
        toolchain: "1.87.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 2,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "riscv32imac-unknown-none-elf",
        priority: 3,
        toolchain: "1.87.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 2,
        extra_cargo_args: &[],
    },
    // Priority 4: 8-bit AVR (nightly-only, needs build-std + target-cpu).
    // Modern rustc uses the `avr-none` triple and requires an explicit
    // `-C target-cpu=<mcu>`. The CI workflow sets RUSTFLAGS accordingly
    // and passes -Z build-std=core via extra_cargo_args.
    TargetSpec {
        triple: "avr-none",
        priority: 4,
        toolchain: "nightly",
        forbidden: mnemonics::AVR_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 1,
        extra_cargo_args: &["-Z", "build-std=core"],
    },
    // Priority 5: aarch64
    TargetSpec {
        triple: "aarch64-unknown-linux-gnu",
        priority: 5,
        toolchain: "1.87.0",
        forbidden: mnemonics::AARCH64_FORBIDDEN,
        allowed_cmov: mnemonics::AARCH64_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    // Priority 6: x86_64
    TargetSpec {
        triple: "x86_64-unknown-linux-gnu",
        priority: 6,
        toolchain: "1.87.0",
        forbidden: mnemonics::X86_64_FORBIDDEN,
        allowed_cmov: mnemonics::X86_64_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    // Host fallback: aarch64-apple-darwin. Same mnemonic tables as
    // aarch64-linux. The CI matrix doesn't run this; it's here so
    // `cargo run -p ct-driver` works on macOS dev boxes without --target.
    TargetSpec {
        triple: "aarch64-apple-darwin",
        priority: 99,
        toolchain: "stable",
        forbidden: mnemonics::AARCH64_FORBIDDEN,
        allowed_cmov: mnemonics::AARCH64_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
];
