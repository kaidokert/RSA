// The magic value we'll use to fill the stack area.
const STACK_WATERMARK: u8 = 0xCE;

// For the ATmega2560, RAMEND is at address 0x21FF.
const RAMEND_ADDR: u16 = 0x21FF;

// Linker symbol that marks the end of the .bss section.
unsafe extern "C" {
    static mut _end: u8;
}

/// Read the current stack pointer via inline assembly.
/// Interrupts are disabled around the two-byte read to prevent a race
/// between SPL and SPH if an ISR fires in between.
#[inline(always)]
fn read_sp() -> u16 {
    let lo: u8;
    let hi: u8;
    unsafe {
        core::arch::asm!("cli"); // disable interrupts
        core::arch::asm!("in {}, 0x3D", out(reg) lo); // SPL
        core::arch::asm!("in {}, 0x3E", out(reg) hi); // SPH
        core::arch::asm!("sei"); // re-enable interrupts
    }
    (hi as u16) << 8 | lo as u16
}

/// Fills the unused RAM (from _end up to current SP) with a magic value.
/// Only paints below the current stack pointer to avoid overwriting live frames.
pub unsafe fn fill_stack_with_watermark() {
    let stack_start_ptr = &raw mut _end as *mut u8;
    // Leave a safety margin below SP for this function's own frame
    let sp = read_sp();
    let safe_end = (sp - 64) as *mut u8; // 64 bytes margin

    unsafe {
        let mut current_ptr = stack_start_ptr;
        while current_ptr < safe_end {
            core::ptr::write_volatile(current_ptr, STACK_WATERMARK);
            current_ptr = current_ptr.add(1);
        }
    }
}

/// Measures the maximum stack usage by finding the "high-water mark".
/// Scans from _end upward; first byte not matching the watermark indicates
/// where the stack grew to. Usage = RAMEND - that address.
pub unsafe fn measure_stack_usage() -> u16 {
    let stack_start_ptr = &raw const _end as *const u8;
    let stack_end_ptr = RAMEND_ADDR as *const u8;

    unsafe {
        let mut current_ptr = stack_start_ptr;
        while current_ptr <= stack_end_ptr {
            if core::ptr::read_volatile(current_ptr) != STACK_WATERMARK {
                return (stack_end_ptr as u16) - (current_ptr as u16);
            }
            current_ptr = current_ptr.add(1);
        }
    }

    0
}
