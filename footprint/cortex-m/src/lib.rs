#![no_std]

use core::fmt::Write;
use core::hint::black_box;
use embedded_measure::report::{Field, MeasurementRecord, Reporter, StackRecord, TextReporter};
#[cfg(feature = "jtrace-f407")]
use embedded_measure::rtt::RttWriter as OutputWriter;
#[cfg(not(feature = "jtrace-f407"))]
use embedded_measure::semihosting::SemihostingWriter as OutputWriter;
use embedded_measure::stack::StackMeasurement;
use embedded_measure::{Measurement, Unit};

pub mod cyclecount;
pub mod stack;

use cyclecount::{CycleCounter, CycleMeasurement};
use stack::paint_stack;

fn init_output() -> OutputWriter {
    #[cfg(not(feature = "jtrace-f407"))]
    {
        embedded_measure::semihosting::init().unwrap().into_inner()
    }
    #[cfg(feature = "jtrace-f407")]
    {
        embedded_measure::rtt::init_blocking().into_inner()
    }
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

    let mut output = init_output();
    let mut reporter = TextReporter::new(&mut output);
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
    writeln!(output, "rsa {}", if result { "ACCEPT" } else { "REJECT" }).unwrap();
    write!(
        output,
        "METRIC stack:{} cycles:{} target:{} backend:{}",
        stack.high_water_bytes,
        elapsed,
        target_arch_name(),
        backend
    )
    .unwrap();
    #[cfg(feature = "jtrace-f407")]
    write!(
        output,
        " dwt_cycles:{} systick_cycles:{}",
        measurement.dwt, measurement.systick
    )
    .unwrap();
    writeln!(output).unwrap();
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
        embedded_measure::semihosting::exit_success();
    } else {
        embedded_measure::semihosting::exit_failure();
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
        embedded_measure::semihosting::exit_success();
    } else {
        embedded_measure::semihosting::exit_failure();
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
    embedded_measure::rtt::print(format_args!("PANIC: {}\n", info));
    loop {
        cortex_m::asm::nop();
    }
}
