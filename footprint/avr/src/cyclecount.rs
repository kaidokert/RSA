//! Wrap-counted timer for AVR.
//!
//! The ATmega2560 Timer/Counter1 is a 16-bit counter that wraps every 65536
//! ticks. With a prescaler of /1024 at 16 MHz, that's about 4.19 seconds
//! between wraps. Operations that take longer than one wrap (e.g. RSA-1024+
//! verification) lose count without overflow tracking.
//!
//! This module counts overflows in a TIMER1_OVF ISR so the elapsed time
//! returned by [`CycleCounter`] is correct even across many wraps.

use arduino_hal::pac::TC1;
use avr_device::interrupt::Mutex;
use core::cell::Cell;

static TIMER1_WRAPS: Mutex<Cell<u32>> = Mutex::new(Cell::new(0));

#[avr_device::interrupt(atmega2560)]
fn TIMER1_OVF() {
    avr_device::interrupt::free(|cs| {
        let cell = TIMER1_WRAPS.borrow(cs);
        cell.set(cell.get().wrapping_add(1));
    });
}

/// Read total ticks (wraps × 65536 + TCNT1) with a consistency check
/// against an overflow interrupt firing between the two reads.
fn read_total(tc1: &TC1) -> u64 {
    loop {
        let wraps1 = avr_device::interrupt::free(|cs| TIMER1_WRAPS.borrow(cs).get());
        let tcnt = tc1.tcnt1.read().bits();
        let wraps2 = avr_device::interrupt::free(|cs| TIMER1_WRAPS.borrow(cs).get());
        if wraps1 == wraps2 {
            return (wraps1 as u64) * 65536 + (tcnt as u64);
        }
    }
}

/// Tick counter that survives Timer1 overflows by counting them in an ISR.
///
/// At 16 MHz with /1024 prescaler each tick is 64 µs.
pub struct CycleCounter {
    start_total: u64,
}

impl CycleCounter {
    /// Configure TC1 with /1024 prescaler, enable the overflow interrupt,
    /// and return a counter snapshotting the current tick count.
    pub fn start(tc1: &TC1) -> Self {
        // Reset wrap counter before enabling interrupts.
        avr_device::interrupt::free(|cs| TIMER1_WRAPS.borrow(cs).set(0));
        tc1.tccr1b.write(|w| w.cs1().prescale_1024());
        // Clear any pending TOV1 flag so we don't count a spurious wrap.
        tc1.tifr1.write(|w| w.tov1().set_bit());
        tc1.timsk1.write(|w| w.toie1().set_bit());
        unsafe {
            avr_device::interrupt::enable();
        }
        Self {
            start_total: read_total(tc1),
        }
    }

    /// Elapsed ticks since [`start`](Self::start).
    pub fn elapsed_ticks(&self, tc1: &TC1) -> u32 {
        (read_total(tc1) - self.start_total) as u32
    }

    /// Elapsed milliseconds. One tick = 64 µs so `ticks * 8 / 125 = ms`.
    pub fn elapsed_ms(&self, tc1: &TC1) -> u32 {
        self.elapsed_ticks(tc1) * 8 / 125
    }
}
