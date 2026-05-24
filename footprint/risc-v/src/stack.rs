unsafe extern "C" {
    static _stack_start: u32;
    static _ram_length: u32;
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
        let stack_start = &_stack_start as *const u32 as *mut u8;
        let stack_size = &_ram_length as *const u32 as usize;
        let stack_end: *mut u8 = stack_start.offset(-(stack_size as isize));
        let safe_stack_end = stack_end.offset(SAFE as isize);

        if stack_size > 2 * SAFE {
            let bytes_to_write = stack_size - (2 * SAFE);
            core::ptr::write_bytes(safe_stack_end, 0xAA, bytes_to_write);
        }
    }
}

pub fn check_stack_high_water_mark_inner<const SAFE: usize>() -> usize {
    unsafe {
        let stack_start = &_stack_start as *const u32 as *mut u8;
        let stack_size = &_ram_length as *const u32 as usize;
        let stack_end = stack_start.offset(-(stack_size as isize));
        let safe_stack_end = stack_end.offset(SAFE as isize);

        let mut current = safe_stack_end;
        while current < stack_start && *current == 0xAA {
            current = current.offset(1);
        }

        stack_start.offset_from(current) as usize
    }
}
