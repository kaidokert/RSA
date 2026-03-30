#![no_std]
#![no_main]

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use rsa::left_pad_noalloc;

#[cortex_m_rt::entry]
fn main() -> ! {
    let mut storage = [0u8; 4];

    let out = left_pad_noalloc(&[1u8], 4, &mut storage).unwrap();
    assert_eq!(out, &[0, 0, 0, 1]);

    let out = left_pad_noalloc(&[0xAA, 0xBB], 2, &mut storage[..2]).unwrap();
    assert_eq!(out, &[0xAA, 0xBB]);

    hprintln!("pad_left ok");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
