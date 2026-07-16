use embedded_measure::stack::{LinkerStack, RiscV, StackConfig, StackProbe};

unsafe extern "C" {
    static _stack_start: u8;
    static _sheap: u8;
}

pub fn paint_stack<const SAFE: usize>() -> StackProbe {
    // SAFETY: riscv-rt defines _sheap as the floor and _stack_start as the top.
    let stack = unsafe {
        LinkerStack::new(
            core::ptr::addr_of!(_sheap).cast_mut(),
            core::ptr::addr_of!(_stack_start).cast_mut(),
            RiscV,
        )
    };
    StackProbe::paint(&stack, StackConfig::new(SAFE)).unwrap()
}
