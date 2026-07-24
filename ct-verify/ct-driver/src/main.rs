//! Secret-exponent ladder assembly gate.

mod target;

use std::path::Path;
use std::process::ExitCode;

use krabi_caliper::host::ct_asm::{run_ladder, DriverConfig, LadderConfig};

fn main() -> ExitCode {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ct-verify workspace");
    run_ladder(
        target::TARGETS,
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
