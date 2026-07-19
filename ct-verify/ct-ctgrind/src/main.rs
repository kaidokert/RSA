use std::process::ExitCode;

mod fixtures;

fn main() -> ExitCode {
    ct_fixtures::link_anchor();
    krabi_caliper::host::ctgrind::run_registered()
}
