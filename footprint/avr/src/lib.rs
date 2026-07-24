#![no_std]
#![feature(abi_avr_interrupt)]
#![feature(asm_experimental_arch)]

use core::hint::black_box;

krabi_caliper::atmega2560_timer1_overflow_handler!();

#[inline(never)]
pub fn fake_verify(modulus: [u8; 64], msg: &[u8], signature: [u8; 64]) -> bool {
    let folded = modulus[0] ^ signature[0] ^ signature[32] ^ (msg.len() as u8);
    black_box(folded);
    true
}

// Panic handler - registered automatically when crate is imported
#[inline(never)]
fn inner_panic_handler() -> ! {
    loop {}
}

#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    inner_panic_handler();
}
