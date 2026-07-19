#![no_std]

use core::fmt::Write;
use core::hint::black_box;
use krabi_caliper::report::{Field, MeasurementRecord, OutcomeRecord, Reporter, StackRecord};
use krabi_caliper::stack::StackMeasurement;
use krabi_caliper::{Measurement, Unit};

pub mod cyclecount;
pub mod stack;

use cyclecount::{CycleCounter, CycleMeasurement};
use stack::paint_stack;

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
    let mut reporter = krabi_caliper::semihosting::init().unwrap();
    #[cfg(feature = "jtrace-f407")]
    let mut reporter = krabi_caliper::rtt::init_blocking();
    reporter
        .stack_measurement(&StackRecord {
            benchmark: "rsa-footprint",
            measurement: stack,
            fields: &fields,
        })
        .unwrap();
    let cycles = Measurement::new(measurement.systick, Unit::CoreCycles);
    #[cfg(feature = "jtrace-f407")]
    let cycles = cycles.with_frequency(16_000_000);
    let systick_fields = [
        Field::token("target", target_arch_name()),
        Field::token("backend", backend),
        Field::token("counter", "systick"),
    ];
    reporter
        .measurement(&MeasurementRecord {
            benchmark: "rsa-footprint",
            measurement: cycles,
            fields: &systick_fields,
        })
        .unwrap();
    #[cfg(feature = "jtrace-f407")]
    reporter
        .measurement(&MeasurementRecord {
            benchmark: "rsa-footprint",
            measurement: Measurement::new(measurement.dwt as u64, Unit::CoreCycles)
                .with_frequency(16_000_000),
            fields: &[
                Field::token("target", target_arch_name()),
                Field::token("backend", backend),
                Field::token("counter", "dwt"),
            ],
        })
        .unwrap();
    writeln!(reporter, "rsa {}", if result { "ACCEPT" } else { "REJECT" }).unwrap();
    write!(
        reporter,
        "METRIC stack:{} cycles:{} target:{} backend:{}",
        stack.high_water_bytes,
        elapsed,
        target_arch_name(),
        backend
    )
    .unwrap();
    #[cfg(feature = "jtrace-f407")]
    write!(
        reporter,
        " dwt_cycles:{} systick_cycles:{}",
        measurement.dwt, measurement.systick
    )
    .unwrap();
    writeln!(reporter).unwrap();
    reporter
        .outcome(&OutcomeRecord {
            benchmark: "rsa-footprint",
            passed: result,
            fields: &fields,
        })
        .unwrap();
}

pub fn test_fixture(testable: fn() -> bool, backend: &str) {
    let stack_probe = paint_stack::<256>();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    let stack = stack_probe.measure();
    report(result, stack, measurement, backend);
    #[cfg(not(feature = "jtrace-f407"))]
    if result {
        krabi_caliper::semihosting::exit_success();
    } else {
        krabi_caliper::semihosting::exit_failure();
    }
}

pub fn test_fixture_arg<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) {
    let stack_probe = paint_stack::<SAFE_ZONE_BYTES>();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    let stack = stack_probe.measure();
    report(result, stack, measurement, backend);
    #[cfg(not(feature = "jtrace-f407"))]
    if result {
        krabi_caliper::semihosting::exit_success();
    } else {
        krabi_caliper::semihosting::exit_failure();
    }
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
    krabi_caliper::rtt::print(format_args!("PANIC: {}\n", info));
    loop {
        cortex_m::asm::nop();
    }
}
