#![no_std]
#![no_main]

use panic_semihosting as _;

#[cortex_m_rt::entry]
fn main() -> ! {
    loop {}
}