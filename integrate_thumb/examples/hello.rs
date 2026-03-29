#![no_std]
#![no_main]

use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;

#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("integrate_thumb hello");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
