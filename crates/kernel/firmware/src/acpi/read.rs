/// Read 4 bytes at `p` and return as a little-endian `u32`.
/// # SAFETY: caller asserts ≥4 bytes readable at `p`.
pub(super) unsafe fn read_u32_le(p: *const u8) -> u32 {
    let mut v = 0u32;
    let mut i = 0u32;
    while i < 4 {
        // SAFETY: caller asserts ≥4 bytes readable; offset i < 4.
        let b = unsafe { core::ptr::read_volatile(p.add(i as usize)) } as u32;
        v |= b << (i * 8);
        i += 1;
    }
    v
}

/// Read 8 bytes at `p` and return as a little-endian `u64`.
/// # SAFETY: caller asserts ≥8 bytes readable at `p`.
pub(super) unsafe fn read_u64_le(p: *const u8) -> u64 {
    let mut v = 0u64;
    let mut i = 0u32;
    while i < 8 {
        // SAFETY: caller asserts ≥8 bytes readable; offset i < 8.
        let b = unsafe { core::ptr::read_volatile(p.add(i as usize)) } as u64;
        v |= b << (i * 8);
        i += 1;
    }
    v
}
