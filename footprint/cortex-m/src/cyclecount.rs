use cortex_m_rt::exception;
use krabi_caliper::cortex_m::systick_overflow;
pub use krabi_caliper::cortex_m::{
    CycleCounters as CycleCounter, CycleMeasurements as CycleMeasurement,
};

#[exception]
fn SysTick() {
    systick_overflow();
}
