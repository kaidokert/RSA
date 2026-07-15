#![no_std]

use core::hint::black_box;
#[cfg(not(feature = "jtrace-f407"))]
use cortex_m_semihosting::{debug, hprintln};
#[cfg(feature = "jtrace-f407")]
use rtt_target::{rprintln, rtt_init_print};

pub mod cyclecount;
pub mod stack;

use cyclecount::{CycleCounter, CycleMeasurement};
use stack::{
    check_stack_high_water_mark, check_stack_high_water_mark_inner, paint_stack, paint_stack_inner,
};

#[cfg(feature = "jtrace-f407")]
fn init_output() {
    rtt_init_print!();
}

pub fn target_arch_name() -> &'static str {
    #[cfg(thumbv6m)]
    {
        "thumbv6m"
    }
    #[cfg(thumbv7m)]
    {
        "thumbv7m"
    }
    #[cfg(thumbv7em)]
    {
        "thumbv7em"
    }
}

fn report(result: bool, stack: usize, measurement: CycleMeasurement, backend: &str) {
    let elapsed = measurement.systick / 1000;

    #[cfg(not(feature = "jtrace-f407"))]
    {
        if result {
            hprintln!("rsa ACCEPT");
        } else {
            hprintln!("rsa REJECT");
        }
        hprintln!(
            "METRIC stack:{} cycles:{} target:{} backend:{}",
            stack,
            elapsed,
            target_arch_name(),
            backend
        );
        if result {
            debug::exit(debug::EXIT_SUCCESS);
        } else {
            debug::exit(debug::EXIT_FAILURE);
        }
    }

    #[cfg(feature = "jtrace-f407")]
    {
        if result {
            rprintln!("rsa ACCEPT");
        } else {
            rprintln!("rsa REJECT");
        }
        rprintln!(
            "METRIC stack:{} cycles:{} target:{} backend:{} dwt_cycles:{} systick_cycles:{}",
            stack,
            elapsed,
            target_arch_name(),
            backend,
            measurement.dwt,
            measurement.systick
        );
    }
}

pub fn test_fixture(testable: fn() -> bool, backend: &str) {
    #[cfg(feature = "jtrace-f407")]
    init_output();
    paint_stack();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    let stack = check_stack_high_water_mark();
    report(result, stack, measurement, backend);
}

pub fn test_fixture_arg<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) {
    #[cfg(feature = "jtrace-f407")]
    init_output();
    paint_stack_inner::<SAFE_ZONE_BYTES>();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    let stack = check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>();
    report(result, stack, measurement, backend);
}

#[inline(never)]
pub fn fake_verify(modulus: [u8; 64], msg: &[u8], signature: [u8; 64]) -> bool {
    let folded = modulus[0] ^ signature[0] ^ signature[32] ^ (msg.len() as u8);
    black_box(folded);
    true
}

#[cfg(not(feature = "jtrace-f407"))]
use panic_semihosting as _;

#[cfg(feature = "jtrace-f407")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    rprintln!("PANIC: {}", info);
    loop {
        cortex_m::asm::nop();
    }
}
