//! Linux implementation — real crabgrind calls.

use std::ffi::c_void;

pub fn is_under_valgrind() -> bool {
    !matches!(crabgrind::run_mode(), crabgrind::RunMode::Native)
}

pub fn count_errors() -> usize {
    crabgrind::count_errors()
}

// A swallowed mark_mem failure would silently untaint a positive
// fixture into a vacuous pass — fail closed instead.
pub fn mark_undefined(addr: *const u8, len: usize) {
    crabgrind::memcheck::mark_mem(
        addr as *mut c_void,
        len,
        crabgrind::memcheck::MemState::Undefined,
    )
    .expect("memcheck mark_mem(Undefined) client request failed");
}

pub fn mark_defined(addr: *const u8, len: usize) {
    crabgrind::memcheck::mark_mem(
        addr as *mut c_void,
        len,
        crabgrind::memcheck::MemState::Defined,
    )
    .expect("memcheck mark_mem(Defined) client request failed");
}
