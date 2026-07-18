use embedded_measure::stack::{CortexM, LinkerStack, StackConfig, StackProbe};

pub fn paint_stack<const SAFE: usize>() -> StackProbe {
    // SAFETY: cortex-m-rt defines the writable descending-stack allocation.
    let stack = unsafe { LinkerStack::<CortexM>::cortex_m_runtime() };
    StackProbe::paint(&stack, StackConfig::new(SAFE)).unwrap()
}
