use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(feature = "jtrace-f407")]
use cortex_m::peripheral::DWT;
use cortex_m::peripheral::{SYST, syst::SystClkSource};
use cortex_m_rt::exception;

static SYSTICK_WRAPS: AtomicU32 = AtomicU32::new(0);

#[exception]
fn SysTick() {
    let current = SYSTICK_WRAPS.load(Ordering::Relaxed);
    SYSTICK_WRAPS.store(current + 1, Ordering::Relaxed);
}

pub struct CycleCounter {
    start_systick: u64,
    #[cfg(feature = "jtrace-f407")]
    start_dwt: u32,
}

pub struct CycleMeasurement {
    pub systick: u64,
    #[cfg(feature = "jtrace-f407")]
    pub dwt: u32,
}

impl CycleCounter {
    const RELOAD_VALUE: u32 = 0x00ff_ffff;

    fn total_cycles() -> u64 {
        let period = Self::RELOAD_VALUE as u64 + 1;
        loop {
            let wraps1 = SYSTICK_WRAPS.load(Ordering::SeqCst);
            let val = SYST::get_current();
            let wraps2 = SYSTICK_WRAPS.load(Ordering::SeqCst);
            if wraps1 == wraps2 {
                return wraps1 as u64 * period + (Self::RELOAD_VALUE as u64 - val as u64);
            }
        }
    }

    pub fn new() -> Self {
        let mut peripherals = cortex_m::Peripherals::take().unwrap();
        let syst = &mut peripherals.SYST;
        syst.set_clock_source(SystClkSource::Core);
        syst.set_reload(Self::RELOAD_VALUE);
        syst.clear_current();
        syst.enable_interrupt();
        syst.enable_counter();

        cortex_m::asm::dsb();
        while SYST::get_current() == 0 {
            cortex_m::asm::nop();
        }

        #[cfg(feature = "jtrace-f407")]
        {
            assert!(DWT::has_cycle_counter());
            peripherals.DCB.enable_trace();
            peripherals.DWT.set_cycle_count(0);
            peripherals.DWT.enable_cycle_counter();
            cortex_m::asm::dsb();
        }

        Self {
            start_systick: Self::total_cycles(),
            #[cfg(feature = "jtrace-f407")]
            start_dwt: DWT::cycle_count(),
        }
    }

    pub fn elapsed(&self) -> CycleMeasurement {
        #[cfg(feature = "jtrace-f407")]
        let dwt = DWT::cycle_count().wrapping_sub(self.start_dwt);
        let systick = Self::total_cycles() - self.start_systick;

        CycleMeasurement {
            systick,
            #[cfg(feature = "jtrace-f407")]
            dwt,
        }
    }
}
