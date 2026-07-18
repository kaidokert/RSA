use embedded_measure::stack::{Avr, LinkerStack, StackConfig, StackMeasurement, StackProbe};

const RAMEND_EXCLUSIVE: usize = 0x2200;

pub fn fill_stack_with_watermark() -> StackProbe {
    let stack = unsafe { LinkerStack::<Avr>::avr_runtime(RAMEND_EXCLUSIVE) };
    StackProbe::paint(&stack, StackConfig::new(64).sentinel(0xce)).unwrap()
}

pub fn measure_stack(probe: &StackProbe) -> StackMeasurement {
    probe.measure()
}
