// Non-coherent DMA cache ownership. DMA-capable drivers must transfer cache
// ownership before a device reads CPU data and before CPU reads device data.

#[cfg(target_arch = "aarch64")]
const CACHE_LINE_BYTES: u64 = 64;

#[cfg(target_arch = "aarch64")]
fn each_line(va: u64, len: usize, mut f: impl FnMut(u64)) {
    if len == 0 { return; }
    let mut line = va & !(CACHE_LINE_BYTES - 1);
    let end = va.saturating_add(len as u64);
    while line < end { f(line); line = line.saturating_add(CACHE_LINE_BYTES); }
}

/// Make CPU-written DMA memory visible before a device reads it. # C: O(cache lines)
pub fn clean_to_device(va: u64, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        each_line(va, len, |line| {
            // SAFETY: caller owns the mapped DMA range until the device completes this transfer.
            unsafe { core::arch::asm!("dc cvac, {x}", x = in(reg) line, options(nostack, preserves_flags)); }
        });
        // SAFETY: orders cache cleaning before the caller rings the device doorbell.
        unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)); }
    }
    #[cfg(not(target_arch = "aarch64"))]
    { let _ = (va, len); core::sync::atomic::fence(core::sync::atomic::Ordering::Release); }
}

/// Discard stale CPU cache lines before reading device-written DMA memory. # C: O(cache lines)
pub fn invalidate_from_device(va: u64, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        each_line(va, len, |line| {
            // SAFETY: caller owns the mapped DMA range and device completion made its contents final.
            unsafe { core::arch::asm!("dc ivac, {x}", x = in(reg) line, options(nostack, preserves_flags)); }
        });
        // SAFETY: completes invalidation before CPU loads observe the DMA range.
        unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)); }
    }
    #[cfg(not(target_arch = "aarch64"))]
    { let _ = (va, len); core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire); }
}
