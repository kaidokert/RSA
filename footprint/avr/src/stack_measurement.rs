// The magic value we'll use to fill the stack area.
const STACK_WATERMARK: u8 = 0xCE;

// For the ATmega2560, RAMEND is at address 0x21FF.
const RAMEND_ADDR: u16 = 0x21FF;

// Linker symbol that marks the end of the .bss section.
unsafe extern "C" {
    static mut _end: u8;
}

/// Read the current stack pointer via inline assembly.
/// Snapshot SREG and restore it after the read so a caller that had IRQs
/// disabled isn't surprised by them turning back on. Prevents an SPL/SPH
/// tearing race if an ISR fires between the two `in` instructions.
#[inline(always)]
fn read_sp() -> u16 {
    let lo: u8;
    let hi: u8;
    unsafe {
        core::arch::asm!(
            "in {sreg}, 0x3F",  // save SREG (I bit) into scratch reg
            "cli",
            "in {lo}, 0x3D",    // SPL
            "in {hi}, 0x3E",    // SPH
            "out 0x3F, {sreg}", // restore SREG from scratch reg
            sreg = out(reg) _,
            lo = out(reg) lo,
            hi = out(reg) hi,
        );
    }
    (hi as u16) << 8 | lo as u16
}

/// Fills the unused RAM (from _end up to current SP) with a magic value.
/// Only paints below the current stack pointer to avoid overwriting live frames.
pub unsafe fn fill_stack_with_watermark() {
    let stack_start_ptr = &raw mut _end as *mut u8;
    // Leave a safety margin below SP for this function's own frame. If SP is
    // already inside the margin, the stack is essentially full — bail out
    // rather than wrap and clobber arbitrary memory.
    let sp = read_sp();
    let safe_end_addr = sp.saturating_sub(64);
    if (safe_end_addr as usize) <= (stack_start_ptr as usize) {
        return;
    }
    let safe_end = safe_end_addr as *mut u8;

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
                // +1 because both endpoints are inclusive — a single used
                // byte at RAMEND should report 1, not 0.
                return (stack_end_ptr as u16) - (current_ptr as u16) + 1;
            }
            current_ptr = current_ptr.add(1);
        }
    }

    0
}
