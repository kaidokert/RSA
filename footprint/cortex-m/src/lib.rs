#![no_std]

use core::hint::black_box;
use cortex_m_semihosting::{debug, hprintln};

pub mod cyclecount;
pub mod stack;

use cyclecount::CycleCounter;
use stack::{
    check_stack_high_water_mark, check_stack_high_water_mark_inner, paint_stack, paint_stack_inner,
};

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

pub fn test_fixture(testable: fn() -> bool, backend: &str) {
    paint_stack();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed = counter.elapsed() / 1000;
    let stack = check_stack_high_water_mark();
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

pub fn test_fixture_arg<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) {
    paint_stack_inner::<SAFE_ZONE_BYTES>();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed = counter.elapsed() / 1000;
    let stack = check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>();
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

#[inline(never)]
pub fn fake_verify(modulus: [u8; 64], msg: &[u8], signature: [u8; 64]) -> bool {
    let folded = modulus[0] ^ signature[0] ^ signature[32] ^ (msg.len() as u8);
    black_box(folded);
    true
}

use panic_semihosting as _;
