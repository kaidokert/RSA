use core::fmt;

const UART0_BASE: usize = 0x10013000;
const TXDATA_OFFSET: usize = 0x00;
const TXCTRL_OFFSET: usize = 0x08;

pub fn uart_init() {
    unsafe {
        let txctrl = (UART0_BASE + TXCTRL_OFFSET) as *mut u32;
        core::ptr::write_volatile(txctrl, 0x1); // txen = 1
    }
}

pub fn uart_putc(c: u8) {
    unsafe {
        let txdata = (UART0_BASE + TXDATA_OFFSET) as *mut u32;
        // Wait until TX FIFO is not full (bit 31)
        while core::ptr::read_volatile(txdata) & (1 << 31) != 0 {}
        core::ptr::write_volatile(txdata, c as u32);
    }
}

pub struct UartWriter;

impl fmt::Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            uart_putc(b);
        }
        Ok(())
    }
}
