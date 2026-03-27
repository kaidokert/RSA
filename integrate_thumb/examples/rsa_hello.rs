#![no_std]
#![no_main]

use panic_semihosting as _;
use rsa::RsaPublicKey;

#[cortex_m_rt::entry]
fn main() -> ! {
    let key = RsaPublicKey::new(2u8.into() , 2u8.into());

    loop {

    }
}