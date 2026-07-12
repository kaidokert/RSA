//! Report shape (JSON + human) for the ladder branch-freedom check.

use serde::Serialize;

use crate::parse::Violation;

#[derive(Debug, Serialize)]
pub struct Report {
    pub target: String,
    /// Ladder symbols matched (must be ≥ 1; zero means the symbol was
    /// inlined away or renamed, and we can no longer confirm it).
    pub ladder_symbols_matched: usize,
    /// Conditional branches observed across ladder bodies.
    pub ladder_branches_seen: usize,
    /// The reviewed-and-documented allowance (the bit-width loop guard).
    pub ladder_branches_allowed: usize,
    /// Negative-control symbols that tripped the mnemonic tables (must
    /// be ≥ 1: proves the tables detect branches on this ISA).
    pub negative_controls_tripped: usize,
    /// Branches beyond the documented allowance — each a real finding
    /// (a candidate secret-dependent branch in the ladder).
    pub ladder_violations: Vec<ViolationOut>,
}

#[derive(Debug, Serialize)]
pub struct ViolationOut {
    pub symbol: String,
    pub offset: String, // hex
    pub insn: String,
    pub context: Vec<String>,
}

impl From<Violation> for ViolationOut {
    fn from(v: Violation) -> Self {
        Self {
            symbol: v.symbol,
            offset: format!("0x{:x}", v.offset),
            insn: v.line.trim().to_string(),
            context: v.context,
        }
    }
}

impl Report {
    pub fn exit_code(&self) -> i32 {
        // Fail closed: a real violation, no ladder symbol to inspect, or
        // a mnemonic-table self-test that didn't fire.
        if !self.ladder_violations.is_empty()
            || self.ladder_symbols_matched == 0
            || self.negative_controls_tripped == 0
        {
            1
        } else {
            0
        }
    }

    pub fn print_human(&self) {
        println!("==== ladder-check report for {} ====", self.target);
        println!(
            "  ladder symbols matched:    {}",
            self.ladder_symbols_matched
        );
        println!(
            "  ladder branches:           {} seen, {} allowed (bit-width loop guard)",
            self.ladder_branches_seen, self.ladder_branches_allowed
        );
        println!(
            "  negative controls tripped: {}",
            self.negative_controls_tripped
        );
        if self.ladder_symbols_matched == 0 {
            println!("  ✗ no ladder symbol found — cannot confirm the secret-exponent path");
        }
        if self.negative_controls_tripped == 0 {
            println!("  ✗ no negative control tripped — mnemonic tables may be blind on this ISA");
        }
        if self.ladder_violations.is_empty() {
            if self.exit_code() == 0 {
                println!("  ladder within allowance:   ✓");
            }
        } else {
            println!(
                "  ladder branches beyond allowance (FORBIDDEN): {}  ✗",
                self.ladder_violations.len()
            );
            for v in &self.ladder_violations {
                println!("    [{}] {} {}", v.offset, v.symbol, v.insn);
                for ctx in &v.context {
                    println!("        | {}", ctx.trim());
                }
            }
        }
    }
}
