/// Clean cache lines to the point of coherency before device reads.
/// # C: O(cache lines)
pub fn clean_to_poc(va: u64, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        const CACHE_LINE_BYTES: u64 = 64;
        if len == 0 {
            return;
        }
        let start = va & !(CACHE_LINE_BYTES - 1);
        let end = va.wrapping_add(len as u64 + CACHE_LINE_BYTES - 1)
            & !(CACHE_LINE_BYTES - 1);
        let mut line = start;
        while line < end {
            // SAFETY: cache maintenance by virtual address for a mapped kernel
            // buffer that will be consumed by GIC/ITS or device DMA.
            unsafe {
                core::arch::asm!(
                    "dc cvac, {x}",
                    x = in(reg) line,
                    options(nostack, preserves_flags),
                );
            }
            line = line.wrapping_add(CACHE_LINE_BYTES);
        }
        // SAFETY: completes cache cleaning before the following MMIO doorbell.
        unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)); }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (va, len);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    }
}
