//! Secret-exponent ladder assembly gate.

mod target;

use std::path::Path;
use std::process::ExitCode;

use krabi_caliper::host::ct_asm::{DriverConfig, LadderConfig, Surface, run_ladder};

fn main() -> ExitCode {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ct-verify workspace");
    // At opt-level "s" the per-limb select loops inline into the ladder;
    // accept loops over public bounds structurally so the budget still
    // counts only the ladder's own bit-loop branch.
    let targets: Vec<_> = target::TARGETS
        .iter()
        .map(|&policy| Surface {
            policy,
            counted_loops: true,
            excluded_fixtures: &[],
        })
        .collect();
    run_ladder(
        &targets,
        LadderConfig {
            driver: DriverConfig {
                workspace,
                fixture_package: "ct-fixtures",
                fixture_features: &["panic-handler"],
            },
            default_ladder: r"Ct\$GT\$3exp17h",
        },
    )
}
