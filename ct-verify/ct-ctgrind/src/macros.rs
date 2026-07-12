//! Registration macro + taint helpers.
//!
//! Every fixture input crosses the C ABI **by pointer** (including the
//! cswap choice byte), so the taint mark on the pointed-to buffer is
//! what the callee reads — there is no by-value register copy for the
//! optimizer to const-propagate past the client request. If a future
//! fixture takes a by-value scalar, it must be initialized through
//! `black_box` (see fixed-bigint's `ctgrind_shift` for the failure
//! mode: release-LTO const-props the literal past `taint_val`, which
//! only sets Valgrind metadata, not memory contents).

/// Registers `run_<name>` into the inventory. The body is the taint
/// wrapper: allocate zeroed buffers, `taint*` the secret ones, call the
/// extern symbol, `untaint*` the outputs, `black_box` them.
macro_rules! ctgrind_fixture {
    ($name:ident, $body:block) => {
        paste::paste! {
            #[allow(non_snake_case)]
            fn [<run_ $name>]() $body
            inventory::submit! {
                crate::Fixture {
                    name: stringify!($name),
                    run: [<run_ $name>],
                }
            }
        }
    };
}
pub(crate) use ctgrind_fixture;

// ============================================================================
// Taint helpers — thin wrappers around crabgrind's memcheck client requests.
// ============================================================================

pub fn taint_val<T>(v: &T) {
    crate::valgrind::mark_undefined(v as *const T as *const u8, size_of::<T>());
}

pub fn untaint_val<T>(v: &T) {
    crate::valgrind::mark_defined(v as *const T as *const u8, size_of::<T>());
}
