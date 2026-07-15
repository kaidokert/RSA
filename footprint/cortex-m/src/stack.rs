unsafe extern "C" {
    static _stack_start: u32;
    static _stack_end: u32;
}

const SAFE_ZONE_BYTES: usize = 256;

#[inline(always)]
pub fn paint_stack() {
    paint_stack_inner::<SAFE_ZONE_BYTES>();
}

#[inline(always)]
pub fn check_stack_high_water_mark() -> usize {
    check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>()
}

pub fn paint_stack_inner<const SAFE: usize>() {
    unsafe {
        let stack_start_addr = &_stack_start as *const u32 as usize;
        let stack_end_addr = &_stack_end as *const u32 as usize;
        let sp: usize;
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
        let live_limit = sp.saturating_sub(SAFE);
        let paint_end_addr = if live_limit < stack_end_addr {
            stack_end_addr
        } else {
            live_limit
        };
        let bytes_to_write = paint_end_addr.saturating_sub(stack_end_addr);

        if bytes_to_write > 0 {
            let stack_start_ptr = &_stack_start as *const u32 as *mut u8;
            let stack_size = stack_start_addr.saturating_sub(stack_end_addr);
            let stack_end_ptr = stack_start_ptr.wrapping_sub(stack_size);
            core::ptr::write_bytes(stack_end_ptr, 0xAA, bytes_to_write);
        }
    }
}

pub fn check_stack_high_water_mark_inner<const SAFE: usize>() -> usize {
    unsafe {
        let stack_start_addr = &_stack_start as *const u32 as usize;
        let stack_end_addr = &_stack_end as *const u32 as usize;
        let stack_size = stack_start_addr.saturating_sub(stack_end_addr);
        let stack_start_ptr = &_stack_start as *const u32 as *mut u8;
        let stack_end_ptr = stack_start_ptr.wrapping_sub(stack_size);

        let mut current = stack_end_ptr;
        while current < stack_start_ptr && core::ptr::read_volatile(current) == 0xAA {
            current = current.wrapping_add(1);
        }

        stack_start_ptr.offset_from(current) as usize
    }
}
