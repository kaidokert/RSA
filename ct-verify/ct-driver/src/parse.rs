//! Disassembly parser.
//!
//! Takes the textual output of `llvm-objdump --disassemble
//! --no-show-raw-insn --no-leading-addr` and splits it into per-symbol
//! function blocks. Then for each block runs the per-target mnemonic
//! check + the thumb IT-state machine + the unconditional-branch
//! direction classifier.

use std::collections::VecDeque;
use std::sync::LazyLock;

use regex::Regex;

use crate::target::TargetSpec;

// Symbol header regex: `<symbol_name>:`. llvm-objdump emits two shapes,
//   `0000000000000020 <_symbol_name>:`        (without --no-leading-addr)
//   `<_symbol_name>:`                         (with --no-leading-addr)
// — both end with `<sym>:`.
static HEADER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([^>]+)>:\s*$").unwrap());

// Instruction line: leading whitespace, then optional `address:`, then the
// mnemonic, then operands. With --no-leading-addr the address is still
// emitted (relative). Be permissive: strip the leading `address:` if
// present, take the first whitespace-delimited token as the mnemonic.
static INSN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:([0-9a-fA-F]+):)?\s+(\S+)(?:\s+(.*))?$").unwrap());

// Relocation line emitted by `objdump -r`, interleaved with disassembly.
// Format varies by file format:
//   Mach-O: `\t\t<addr>:  ARM64_RELOC_BRANCH26\t<symbol>`
//   ELF:    `\t\t<addr>: R_AARCH64_CALL26\t<symbol>` (and other R_*)
// Common shape: indented line, optional `addr:`, a relocation type
// (token containing `RELOC` or starting with `R_`), then a symbol.

/// One disassembled function block.
#[derive(Debug)]
pub struct FunctionBlock {
    pub symbol: String,
    /// Each line: (offset_hex_string, mnemonic, full_line_text).
    pub insns: Vec<Insn>,
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub offset: u64,
    pub mnemonic: String,
    pub full_line: String,
}

/// Parse the entire objdump output into function blocks.
pub fn split_blocks(objdump_out: &str) -> Vec<FunctionBlock> {
    let mut blocks: Vec<FunctionBlock> = Vec::new();
    let mut current: Option<FunctionBlock> = None;
    let mut implicit_offset: u64 = 0;

    for line in objdump_out.lines() {
        // Skip dividers and headers from the archive listing.
        if line.is_empty()
            || line.starts_with("Disassembly")
            || line.starts_with(';')
            || line.contains(":\tfile format ")
        {
            continue;
        }

        if let Some(caps) = HEADER_RE.captures(line) {
            // Flush previous block.
            if let Some(b) = current.take() {
                blocks.push(b);
            }
            let sym = caps.get(1).unwrap().as_str().to_string();
            current = Some(FunctionBlock {
                symbol: sym,
                insns: Vec::new(),
            });
            implicit_offset = 0;
            continue;
        }

        let Some(block) = current.as_mut() else {
            continue;
        };

        if let Some(caps) = INSN_RE.captures(line) {
            let offset = if let Some(parsed) = caps
                .get(1)
                .and_then(|m| u64::from_str_radix(m.as_str(), 16).ok())
            {
                // Keep implicit_offset in sync so a subsequent
                // address-less line continues from the right place.
                implicit_offset = parsed + 4;
                parsed
            } else {
                let o = implicit_offset;
                implicit_offset += 4; // arbitrary default; only used when address column is missing
                o
            };
            let mnemonic = caps
                .get(2)
                .map(|m| m.as_str().to_ascii_lowercase())
                .unwrap_or_default();
            // Skip lines that aren't actually instructions (e.g.,
            // `...` continuation lines from llvm-objdump).
            if mnemonic.is_empty() || mnemonic == "..." {
                continue;
            }
            block.insns.push(Insn {
                offset,
                mnemonic,
                full_line: line.trim_end().to_string(),
            });
        }
    }

    if let Some(b) = current.take() {
        blocks.push(b);
    }
    blocks
}

/// One detected branch violation.
#[allow(dead_code)] // `mnemonic` is used by `report.rs::ViolationOut` via `From`.
#[derive(Debug, Clone)]
pub struct Violation {
    pub symbol: String,
    pub offset: u64,
    pub mnemonic: String,
    pub line: String,
    /// The previous 2 instructions + the violating one, for review.
    pub context: Vec<String>,
}

/// Compiled regex set for a target.
pub struct Patterns {
    pub forbidden: Vec<Regex>,
    pub allowed: Vec<Regex>,
}

impl Patterns {
    pub fn build(spec: &TargetSpec) -> Self {
        Self {
            forbidden: spec
                .forbidden
                .iter()
                .map(|p| Regex::new(p).expect("bad forbidden regex"))
                .collect(),
            allowed: spec
                .allowed_cmov
                .iter()
                .map(|p| Regex::new(p).expect("bad allowed regex"))
                .collect(),
        }
    }

    pub fn forbidden_matches(&self, mnemonic: &str) -> bool {
        self.forbidden.iter().any(|r| r.is_match(mnemonic))
    }

    pub fn allowed_matches(&self, mnemonic: &str) -> bool {
        self.allowed.iter().any(|r| r.is_match(mnemonic))
    }
}

/// Scan one block for violations, applying the per-target rules.
pub fn scan_block(block: &FunctionBlock, pat: &Patterns) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut recent: VecDeque<String> = VecDeque::with_capacity(3);

    for insn in &block.insns {
        recent.push_back(insn.full_line.clone());
        if recent.len() > 3 {
            recent.pop_front();
        }

        let m = insn.mnemonic.as_str();

        // Branchless conditional execution — the CT-safe select. On
        // Thumb these are the `it`/`itt`/… headers; the predicated
        // *data-processing* instructions they guard (`moveq`, `addeq`,
        // …) aren't in any forbidden table, so they fall through and are
        // ignored. We deliberately do NOT exempt a forbidden mnemonic
        // just because an IT block is active: an IT-predicated `b<cc>`
        // is still conditional control flow, and a secret-dependent one
        // is exactly the leak this gate exists to catch.
        if pat.allowed_matches(m) {
            continue;
        }

        if pat.forbidden_matches(m) {
            violations.push(Violation {
                symbol: block.symbol.clone(),
                offset: insn.offset,
                mnemonic: insn.mnemonic.clone(),
                line: insn.full_line.clone(),
                context: recent.iter().cloned().collect(),
            });
        }
    }

    violations
}

/// True if a `nct_fix__neg__*` symbol — the negative controls.
pub fn is_negative_control(sym: &str) -> bool {
    sym.starts_with("nct_fix__neg__") || sym.starts_with("_nct_fix__neg__")
}
