#[cfg(target_arch = "aarch64")]
const CACHE_LINE_BYTES: u64 = 64;

#[cfg(target_arch = "aarch64")]
fn each_line(va: u64, len: usize, mut f: impl FnMut(u64)) {
    if len == 0 { return; }
    let mut p = va & !(CACHE_LINE_BYTES - 1);
    let end = va.saturating_add(len as u64);
    while p < end {
        f(p);
        p = p.saturating_add(CACHE_LINE_BYTES);
    }
}

/// Clean CPU-written DMA memory to PoC before a virtio device reads it.
/// # C: O(cache_lines)
pub fn clean_to_device(va: u64, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        each_line(va, len, |line| {
            // SAFETY: caller provides a mapped kernel VA range owned by this
            // driver. `dc cvac` makes CPU writes visible to device DMA.
            unsafe { core::arch::asm!("dc cvac, {x}", x = in(reg) line, options(nostack, preserves_flags)); }
        });
        // SAFETY: completes cache maintenance before the following MMIO notify.
        unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)); }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (va, len);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    }
}

/// Invalidate device-written DMA memory before the CPU reads it.
/// # C: O(cache_lines)
pub fn invalidate_from_device(va: u64, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        each_line(va, len, |line| {
            // SAFETY: caller provides a mapped device-written DMA range.
            // `dc ivac` discards stale CPU lines before CPU reads.
            unsafe { core::arch::asm!("dc ivac, {x}", x = in(reg) line, options(nostack, preserves_flags)); }
        });
        // SAFETY: completes invalidation before subsequent CPU loads.
        unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)); }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (va, len);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    }
}
