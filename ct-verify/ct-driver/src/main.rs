//! Ladder branch-freedom check.
//!
//! A narrow, targeted check — NOT a whole-operation gate. A whole RSA
//! sign is full of legitimate branches on public data (padding lengths,
//! key structure, the public verify exponent, honest-`Option`
//! boundaries), so asm-grep-for-any-branch produces only false
//! positives at that granularity; secret-vs-public branch discrimination
//! is the taint (ctgrind) layer's job. The one thing asm-grep does
//! prove cheaply is that the **secret-exponent ladder** — the
//! always-square-always-multiply that raises the message to `d` — emits
//! zero data-dependent branches, as composed into our archive at our
//! deployment carrier.
//!
//! Per target:
//!   1. `cargo build --release --target=<triple> -p ct-fixtures`
//!   2. find the resulting libct_fixtures.a
//!   3. llvm-objdump --disassemble
//!   4. assert every ladder-symbol body is branch-free (per-ISA mnemonic
//!      tables; an IT-predicated branch still counts), fail closed unless
//!      exactly one ladder monomorphization per positive fixture is present
//!      (fewer = some carrier's ladder was inlined away / renamed → that
//!      carrier's attestation would be vacuous)
//!   5. self-test: assert the negative controls still trip the tables
//!   6. emit JSON report; exit non-zero on any of the above

mod target;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::target::{lookup, TargetSpec, TARGETS};
use krabi_caliper::host::ct_asm::{
    self as parse, LadderReport as Report, Patterns, Violation, ViolationOut,
};

/// Default match for the secret-exponent ladder symbol. modmath's CT
/// exponentiation is `Field::<T, Ct>::exp`; the mangled form ends
/// `..Ct$GT$3exp17h<hash>E` (the `3exp` length prefix distinguishes the
/// bare secret ladder from `14exp_public_exp`, the vartime *public*
/// exponent used by verify-after-sign). Overridable with `--ladder`.
const DEFAULT_LADDER: &str = r"Ct\$GT\$3exp17h";

#[derive(Default)]
struct Args {
    target: Option<String>,
    json_out: Option<PathBuf>,
    list_targets: bool,
    skip_build: bool,
    archive_override: Option<PathBuf>,
    ladder: Option<String>,
    expect_ladder: Option<usize>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--target" => {
                args.target = Some(it.next().ok_or("--target requires a triple")?);
            }
            "--json-out" => {
                args.json_out = Some(PathBuf::from(
                    it.next().ok_or("--json-out requires a path")?,
                ));
            }
            "--list-targets" => args.list_targets = true,
            "--skip-build" => args.skip_build = true,
            "--archive" => {
                args.archive_override =
                    Some(PathBuf::from(it.next().ok_or("--archive requires a path")?));
            }
            "--ladder" => {
                args.ladder = Some(it.next().ok_or("--ladder requires a regex")?);
            }
            "--expect-ladder" => {
                args.expect_ladder = Some(
                    it.next()
                        .ok_or("--expect-ladder requires a count")?
                        .parse()
                        .map_err(|_| "--expect-ladder requires an integer")?,
                );
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {}", other)),
        }
    }
    Ok(args)
}

fn print_help() {
    eprintln!(
        "ct-driver — disassemble ct-fixtures and gate on forbidden conditional branches.\n\
         \n\
         Usage:\n\
           ct-driver --target <TRIPLE> [--json-out <PATH>] [--skip-build] [--archive <PATH>]\n\
           ct-driver --list-targets\n\
           ct-driver -h | --help\n\
         \n\
         Options:\n\
           --target <TRIPLE>   Cargo target triple to verify (use --list-targets for the list).\n\
                               If omitted, the host triple (rustc -vV → host) is used.\n\
           --json-out <PATH>   Write JSON report to PATH (also written to stdout in human form).\n\
           --skip-build        Don't run cargo build; reuse the existing libct_fixtures.a.\n\
           --archive <PATH>    Override the path to libct_fixtures.a (for debugging).\n\
           --expect-ladder <N> Expected ladder monomorphization count (default: one per\n\
                               ct_fix__* positive fixture found in the archive).\n\
         \n\
         Exit code 0 = clean. Non-zero = ct violations OR negative controls didn't trip."
    );
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            print_help();
            return ExitCode::from(2);
        }
    };

    if args.list_targets {
        for t in TARGETS {
            println!(
                "[{}] {}  (toolchain: {})",
                t.priority, t.triple, t.toolchain
            );
        }
        return ExitCode::SUCCESS;
    }

    let triple = args
        .target
        .clone()
        .unwrap_or_else(|| host_triple().unwrap_or_else(|| "x86_64-unknown-linux-gnu".to_string()));

    let Some(spec) = lookup(&triple) else {
        eprintln!(
            "error: unknown target triple '{}'. Use --list-targets to see supported ones.",
            triple
        );
        return ExitCode::from(2);
    };

    // 1. Build (unless skipped).
    if !args.skip_build {
        if let Err(e) = cargo_build_fixtures(spec) {
            eprintln!("error: cargo build failed: {}", e);
            return ExitCode::from(3);
        }
    }

    // 2. Locate the staticlib.
    let archive = if let Some(p) = args.archive_override.clone() {
        p
    } else {
        match find_archive(spec) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: locating libct_fixtures.a: {}", e);
                return ExitCode::from(3);
            }
        }
    };

    // 3. Disassemble.
    let objdump_text = match run_objdump(&archive) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: llvm-objdump failed: {}", e);
            return ExitCode::from(3);
        }
    };

    // 4. Parse + scan.
    let blocks = parse::split_blocks(&objdump_text);
    let pat = Patterns::new(spec.forbidden, spec.allowed_cmov, &[], &[], &[]);
    let ladder_re = match regex::Regex::new(args.ladder.as_deref().unwrap_or(DEFAULT_LADDER)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: bad --ladder regex: {}", e);
            return ExitCode::from(2);
        }
    };

    let mut ladder_symbols_matched: usize = 0;
    let mut ladder_branches_seen: usize = 0;
    let mut ladder_violations: Vec<Violation> = Vec::new();
    let mut negative_controls_tripped: usize = 0;
    let mut positive_fixtures: usize = 0;

    for block in &blocks {
        // The secret-exponent ladder: at most the reviewed loop-control
        // branches, no more. The allowance applies *per block* — if the
        // ladder is monomorphized for several carriers, each
        // instantiation gets its own count rather than sharing one pool.
        if ladder_re.is_match(&block.symbol) {
            ladder_symbols_matched += 1;
            let mut branches = parse::scan_block(block, &pat, spec.triple.starts_with("thumb"));
            ladder_branches_seen += branches.len();
            if branches.len() > spec.ladder_allowed_branches {
                ladder_violations.extend(branches.split_off(spec.ladder_allowed_branches));
            }
            continue;
        }
        if parse::is_positive_fixture(&block.symbol) {
            positive_fixtures += 1;
        }
        // Negative controls: the mnemonic-table self-test. At least one
        // must trip, proving the tables detect branches on this ISA.
        if parse::is_negative_control(&block.symbol)
            && !parse::scan_block(block, &pat, spec.triple.starts_with("thumb")).is_empty()
        {
            negative_controls_tripped += 1;
        }
    }

    // Each positive fixture pins one carrier, hence one distinct ladder
    // monomorphization; fewer matches than that means some carrier's
    // ladder was inlined/renamed/DCE'd and its attestation would be
    // vacuous. `--expect-ladder` overrides for the day two fixtures
    // legitimately share a carrier (or LLVM merges identical bodies).
    let ladder_symbols_expected = args.expect_ladder.unwrap_or(positive_fixtures);

    // 5. Emit report.
    let report = Report {
        target: triple.clone(),
        ladder_symbols_matched,
        ladder_symbols_expected,
        ladder_branches_seen,
        ladder_branches_allowed: spec.ladder_allowed_branches,
        negative_controls_tripped,
        ladder_violations: ladder_violations
            .into_iter()
            .map(ViolationOut::from)
            .collect(),
    };
    report.print_human();

    if let Some(path) = args.json_out.as_ref() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::File::create(path) {
            Ok(f) => {
                if let Err(e) = serde_json::to_writer_pretty(f, &report) {
                    eprintln!("warning: writing JSON report failed: {}", e);
                }
            }
            Err(e) => eprintln!("warning: creating JSON report file failed: {}", e),
        }
    }

    if report.exit_code() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn host_triple() -> Option<String> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("host: ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn cargo_build_fixtures(spec: &TargetSpec) -> Result<(), String> {
    let host = host_triple().unwrap_or_default();
    let mut cmd = Command::new(env!("CARGO"));
    cmd.arg("build")
        .arg("--release")
        .arg("-p")
        .arg("ct-fixtures")
        // no_std + local panic handler for the staticlib. Not a default
        // feature: ct-ctgrind links the same crate into a std binary
        // where a second panic handler would collide.
        .arg("--features")
        .arg("panic-handler");

    // Only pass --target if it differs from host (otherwise we end up
    // building in `target/release/` rather than `target/<triple>/release/`,
    // which find_archive accounts for, but passing --target=host is also
    // fine and produces the per-triple path).
    if spec.triple != host {
        cmd.arg("--target").arg(spec.triple);
    }
    for a in spec.extra_cargo_args {
        cmd.arg(a);
    }

    eprintln!(
        "[ct-driver] cargo {}",
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let status = cmd.status().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("cargo build exited with {}", status));
    }
    Ok(())
}

fn workspace_target_dir() -> PathBuf {
    // `ct-verify/` is its own nested workspace, so its target dir is
    // `ct-verify/target/`. We're the member at `ct-verify/ct-driver/`,
    // so walk up one level to the workspace root and add `target`.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest);
    root.join("target")
}

fn find_archive(spec: &TargetSpec) -> Result<PathBuf, String> {
    let host = host_triple().unwrap_or_default();
    let target_dir = workspace_target_dir();
    let archive_subpath = "release/libct_fixtures.a";

    let candidates: Vec<PathBuf> = if spec.triple == host {
        vec![
            target_dir.join(archive_subpath),
            target_dir.join(spec.triple).join(archive_subpath),
        ]
    } else {
        vec![target_dir.join(spec.triple).join(archive_subpath)]
    };

    for c in &candidates {
        if c.exists() {
            return Ok(c.clone());
        }
    }
    Err(format!(
        "could not find libct_fixtures.a — tried: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn llvm_objdump_path() -> Result<PathBuf, String> {
    // Prefer the llvm-tools-preview component (matches the toolchain).
    if let Ok(out) = Command::new("rustc").arg("--print").arg("sysroot").output() {
        if out.status.success() {
            let sysroot = String::from_utf8_lossy(&out.stdout).trim().to_string();
            // The llvm-tools-preview component installs binaries under
            //   <sysroot>/lib/rustlib/<host>/bin/llvm-objdump
            let host = host_triple().unwrap_or_default();
            let candidate = Path::new(&sysroot)
                .join("lib")
                .join("rustlib")
                .join(&host)
                .join("bin")
                .join(format!("llvm-objdump{}", std::env::consts::EXE_SUFFIX));
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    // Fall back to PATH lookup at exec time. If neither name resolves
    // run_objdump will surface a clear "No such file" error.
    Ok(PathBuf::from("llvm-objdump"))
}

fn run_objdump(archive: &Path) -> Result<String, String> {
    let tool = llvm_objdump_path()?;

    // No explicit --triple/--arch: llvm-objdump auto-detects the
    // architecture per-object from the archive's ELF headers, AVR
    // included (verified identical to an explicit flag).
    let mut cmd = Command::new(&tool);
    cmd.arg("--disassemble").arg("--no-show-raw-insn");
    cmd.arg(archive);

    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "llvm-objdump failed: status={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
