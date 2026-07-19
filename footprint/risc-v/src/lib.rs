#![no_std]

use core::fmt::Write;
use core::hint::black_box;
use krabi_caliper::Counter;
use krabi_caliper::report::{Field, MeasurementRecord, OutcomeRecord, Reporter, StackRecord};
use krabi_caliper::risc_v::{McycleCounter, MinstretCounter};

pub mod stack;
pub mod uart;

pub const MODULUS: [u8; 64] = [
    0x96, 0x9d, 0x03, 0xff, 0xa9, 0x8d, 0x88, 0x8f, 0x3a, 0xa4, 0xf2, 0xfe, 0xd2, 0x32, 0xe6, 0x1c,
    0x4a, 0xcf, 0x06, 0x63, 0xa9, 0x2f, 0x99, 0x03, 0x4c, 0xf7, 0xb7, 0x24, 0x5a, 0x1a, 0x1e, 0x5e,
    0xaf, 0xa5, 0x65, 0xaf, 0xb9, 0x0b, 0xab, 0x22, 0x85, 0x71, 0x2f, 0xaa, 0x50, 0x39, 0x39, 0xa0,
    0x65, 0xfb, 0x60, 0xdd, 0x08, 0x28, 0xa3, 0x84, 0xf2, 0x6d, 0x8a, 0xfc, 0x28, 0x6d, 0xf6, 0xcf,
];
pub const SIGNATURE: [u8; 64] = [
    0x45, 0x53, 0xf3, 0xaf, 0x16, 0xaf, 0x63, 0x97, 0xb0, 0xd3, 0x2f, 0x8a, 0xec, 0xd5, 0x4c, 0xf1,
    0xf3, 0xd0, 0x0c, 0x9f, 0x42, 0xdc, 0x68, 0xcb, 0xd7, 0x05, 0xce, 0xa5, 0xa9, 0x70, 0x95, 0x3e,
    0xc0, 0xbc, 0x4a, 0x18, 0xed, 0x91, 0xa3, 0x5d, 0x66, 0xec, 0xda, 0x4a, 0x83, 0x32, 0xcf, 0xc3,
    0xa3, 0xab, 0x21, 0xad, 0x59, 0xb2, 0x2e, 0x87, 0xc2, 0x73, 0xff, 0x08, 0x88, 0xdd, 0x4d, 0xe0,
];
pub const MESSAGE: &[u8] = b"hello world!";

use stack::paint_stack;
use uart::{uart_init, uart_reporter};

pub fn test_fixture(testable: fn() -> bool, backend: &str) -> ! {
    uart_init();

    let stack_probe = paint_stack::<256>();
    let mut counter = McycleCounter::new(None);
    let mut instructions = MinstretCounter::new(None);
    let start = counter.now();
    let instructions_start = instructions.now();
    let result = testable();
    let instruction_measurement = instructions.elapsed(instructions_start);
    let measurement = counter.elapsed(start);
    let elapsed = measurement.ticks / 1000;
    let stack = stack_probe.measure();

    let mut reporter = uart_reporter();
    reporter
        .stack_measurement(&StackRecord {
            benchmark: "rsa-footprint",
            measurement: stack,
            fields: &[
                Field::token("target", "riscv32"),
                Field::token("backend", backend),
            ],
        })
        .unwrap();
    reporter
        .measurement(&MeasurementRecord {
            benchmark: "rsa-footprint",
            measurement: instruction_measurement,
            fields: &[
                Field::token("target", "riscv32"),
                Field::token("backend", backend),
                Field::token("counter", "minstret"),
            ],
        })
        .unwrap();
    reporter
        .measurement(&MeasurementRecord {
            benchmark: "rsa-footprint",
            measurement,
            fields: &[
                Field::token("target", "riscv32"),
                Field::token("backend", backend),
                Field::token("counter", "mcycle"),
            ],
        })
        .unwrap();
    if result {
        let _ = writeln!(reporter, "rsa ACCEPT");
    } else {
        let _ = writeln!(reporter, "rsa REJECT");
    }
    let _ = write!(
        reporter,
        "METRIC stack:{} cycles:{} target:riscv32 backend:",
        stack.high_water_bytes, elapsed
    );
    let _ = reporter.write_str(backend);
    let _ = reporter.write_str("\n");
    reporter
        .outcome(&OutcomeRecord {
            benchmark: "rsa-footprint",
            passed: result,
            fields: &[
                Field::token("target", "riscv32"),
                Field::token("backend", backend),
            ],
        })
        .unwrap();

    // sifive_e has no exit mechanism — loop forever, wrapper kills QEMU
    loop {
        unsafe { core::arch::asm!("wfi") }
    }
}

#[inline(never)]
pub fn fake_verify(modulus: [u8; 64], msg: &[u8], signature: [u8; 64]) -> bool {
    let folded = modulus[0] ^ signature[0] ^ signature[32] ^ (msg.len() as u8);
    black_box(folded);
    true
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    uart_init();
    let mut reporter = uart_reporter();
    let _ = writeln!(reporter, "PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("wfi") }
    }
}
