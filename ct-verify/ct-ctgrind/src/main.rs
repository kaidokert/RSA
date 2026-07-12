//! ct-ctgrind — Valgrind-based taint verifier for modmath CT primitives.
//!
//! Each fixture from `ct-fixtures` is called with its secret inputs
//! tagged `MAKE_MEM_UNDEFINED` via crabgrind. Valgrind then flags any
//! conditional jump or memory access that depends on those tainted
//! bytes. The driver reads Valgrind's error counter between fixtures to
//! attribute violations.
//!
//! Run as: `valgrind --tool=memcheck --error-limit=no --error-exitcode=0 ct-ctgrind`.
//! `--error-exitcode=0` is important — we want Valgrind to NOT set the
//! process exit code, because we decide pass/fail ourselves based on
//! which fixtures (positive or negative) tripped. `--error-limit=no` is
//! equally load-bearing: memcheck stops collecting after 1,000 distinct
//! error contexts (or 10M total), and a saturated counter would make
//! every later fixture read as clean — false passes.

use std::process::ExitCode;

mod macros;
mod valgrind;

mod fixtures;

pub struct Fixture {
    pub name: &'static str,
    pub run: fn(),
}

inventory::collect!(Fixture);

fn is_positive(name: &str) -> bool {
    name.starts_with("ct_fix__")
}

fn is_negative(name: &str) -> bool {
    name.starts_with("nct_fix__neg__")
}

fn main() -> ExitCode {
    // Force the fixtures rlib onto the link line (see `link_anchor`).
    ct_fixtures::link_anchor();

    if !valgrind::is_under_valgrind() {
        eprintln!(
            "error: ct-ctgrind must be run under valgrind \
             (e.g. `valgrind --tool=memcheck --error-limit=no --error-exitcode=0 ct-ctgrind`)"
        );
        return ExitCode::from(2);
    }

    let mut pos_pass: usize = 0;
    let mut pos_fail: Vec<&'static str> = Vec::new();
    let mut neg_seen: usize = 0;
    let mut neg_no_trip: Vec<&'static str> = Vec::new();
    let mut unclassified: Vec<&'static str> = Vec::new();

    // inventory's iteration order is link-dependent; sort so reports
    // are comparable across runs and platforms.
    let mut fixtures: Vec<&Fixture> = inventory::iter::<Fixture>().collect();
    fixtures.sort_by_key(|f| f.name);

    for fixture in fixtures {
        let before = valgrind::count_errors();
        (fixture.run)();
        let after = valgrind::count_errors();
        let tripped = after > before;

        if is_positive(fixture.name) {
            if tripped {
                pos_fail.push(fixture.name);
            } else {
                pos_pass += 1;
            }
        } else if is_negative(fixture.name) {
            neg_seen += 1;
            if !tripped {
                neg_no_trip.push(fixture.name);
            }
        } else {
            // Fail closed — a fixture whose name matches neither prefix is
            // almost certainly a rename/typo that would otherwise vanish
            // from coverage silently.
            unclassified.push(fixture.name);
        }
    }

    println!("==== CT-ctgrind report ====");
    println!(
        "  ct_fix__*       passed: {}  failed: {}",
        pos_pass,
        pos_fail.len()
    );
    println!(
        "  nct_fix__neg__* tripped: {}/{}",
        neg_seen - neg_no_trip.len(),
        neg_seen
    );
    for f in &pos_fail {
        println!("    FAIL (positive tripped Valgrind): {}", f);
    }
    for f in &neg_no_trip {
        println!("    FAIL (negative didn't trip): {}", f);
    }
    for f in &unclassified {
        println!("    FAIL (unclassified fixture name): {}", f);
    }

    if pos_pass + pos_fail.len() == 0 {
        eprintln!("error: no positive fixtures registered — registry empty?");
        return ExitCode::FAILURE;
    }
    if neg_seen == 0 {
        eprintln!("error: no negative controls registered — registry empty?");
        return ExitCode::FAILURE;
    }
    if !pos_fail.is_empty() || !neg_no_trip.is_empty() || !unclassified.is_empty() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
