use embedded_measure::stack::{LinkerStack, RiscV, StackConfig, StackProbe};

pub fn paint_stack<const SAFE: usize>() -> StackProbe {
    // SAFETY: riscv-rt defines _sheap as the floor and _stack_start as the top.
    let stack = unsafe { LinkerStack::<RiscV>::riscv_runtime() };
    StackProbe::paint(&stack, StackConfig::new(SAFE)).unwrap()
}
