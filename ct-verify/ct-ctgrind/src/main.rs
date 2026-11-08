use std::process::ExitCode;

mod fixtures;

/// Untaint a value the library declares public by design.
fn declassify(ptr: *const u8, len: usize) {
    // SAFETY: the library passes the address and size of a live value.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    krabi_caliper::host::ctgrind::untaint(bytes);
}

fn main() -> ExitCode {
    ct_fixtures::link_anchor();
    rsa::ct_probe::set_declassifier(declassify);
    krabi_caliper::host::ctgrind::run_registered()
}
