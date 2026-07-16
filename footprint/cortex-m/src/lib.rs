#![no_std]

use core::hint::black_box;
#[cfg(not(feature = "jtrace-f407"))]
use cortex_m_semihosting::{debug, hio, hprintln};
use embedded_measure::report::{Field, Reporter, StackRecord, TextReporter};
use embedded_measure::stack::StackMeasurement;
#[cfg(feature = "jtrace-f407")]
use rtt_target::{rprintln, rtt_init_print};

pub mod cyclecount;
pub mod stack;

use cyclecount::{CycleCounter, CycleMeasurement};
use stack::paint_stack;

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

fn report(result: bool, stack: StackMeasurement, measurement: CycleMeasurement, backend: &str) {
    let elapsed = measurement.systick / 1000;
    let fields = [
        Field::token("target", target_arch_name()),
        Field::token("backend", backend),
    ];

    #[cfg(not(feature = "jtrace-f407"))]
    {
        TextReporter::new(hio::hstdout().unwrap())
            .stack_measurement(&StackRecord {
                benchmark: "rsa-footprint",
                measurement: stack,
                fields: &fields,
            })
            .unwrap();
        if result {
            hprintln!("rsa ACCEPT");
        } else {
            hprintln!("rsa REJECT");
        }
        hprintln!(
            "METRIC stack:{} cycles:{} target:{} backend:{}",
            stack.high_water_bytes,
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
        TextReporter::new(embedded_measure::rtt::RttWriter)
            .stack_measurement(&StackRecord {
                benchmark: "rsa-footprint",
                measurement: stack,
                fields: &fields,
            })
            .unwrap();
        if result {
            rprintln!("rsa ACCEPT");
        } else {
            rprintln!("rsa REJECT");
        }
        rprintln!(
            "METRIC stack:{} cycles:{} target:{} backend:{} dwt_cycles:{} systick_cycles:{}",
            stack.high_water_bytes,
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
    let stack_probe = paint_stack::<256>();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    let stack = stack_probe.measure();
    report(result, stack, measurement, backend);
}

pub fn test_fixture_arg<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) {
    #[cfg(feature = "jtrace-f407")]
    init_output();
    let stack_probe = paint_stack::<SAFE_ZONE_BYTES>();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    let stack = stack_probe.measure();
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
