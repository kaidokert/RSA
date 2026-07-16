use embedded_measure::stack::{CortexM, LinkerStack, StackConfig, StackProbe};

unsafe extern "C" {
    static _stack_start: u8;
    static _stack_end: u8;
}

pub fn paint_stack<const SAFE: usize>() -> StackProbe {
    // SAFETY: cortex-m-rt defines the writable descending-stack allocation.
    let stack = unsafe {
        LinkerStack::new(
            core::ptr::addr_of!(_stack_end).cast_mut(),
            core::ptr::addr_of!(_stack_start).cast_mut(),
            CortexM,
        )
    };
    StackProbe::paint(&stack, StackConfig::new(SAFE)).unwrap()
}
