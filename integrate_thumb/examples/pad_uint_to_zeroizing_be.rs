#![no_std]
#![no_main]

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use rsa::{WrapU8, uint_to_zeroizing_be_pad_noalloc};

#[cortex_m_rt::entry]
fn main() -> ! {
    let mut storage = [0u8; 4];

    let out = uint_to_zeroizing_be_pad_noalloc::<WrapU8>(1u8.into(), 4, &mut storage).unwrap();
    assert_eq!(out, &[0, 0, 0, 1]);

    let out = uint_to_zeroizing_be_pad_noalloc::<WrapU8>(0xABu8.into(), 1, &mut storage[..1]).unwrap();
    assert_eq!(out, &[0xAB]);

    hprintln!("pad_uint_to_zeroizing_be ok");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
