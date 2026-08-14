#[cfg(target_arch = "x86_64")]
const CACHE_LINE_BYTES: u64 = 64;

/// Return whether this architecture can make non-coherent VT-d table writes visible. # C: O(1)
pub(crate) const fn maintenance_available(coherent: bool) -> bool { coherent || cfg!(target_arch = "x86_64") }

/// Publish an owned VT-d table range before hardware can consume it. # C: O(cache lines)
pub(crate) fn publish(hhdm_offset: u64, pa: u64, bytes: u64, coherent: bool) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    if coherent { return; }
    #[cfg(target_arch = "x86_64")]
    {
        let Some(end) = pa.checked_add(bytes) else { return; };
        let mut current = pa & !(CACHE_LINE_BYTES - 1);
        while current < end {
            let va = hhdm_offset.wrapping_add(current) as *const u8;
            // SAFETY: `va` names one cache line of the caller's owned VT-d table allocation.
            unsafe { core::arch::asm!("clflush [{}]", in(reg) va, options(nostack, preserves_flags)); }
            current += CACHE_LINE_BYTES;
        }
        // SAFETY: MFENCE orders the completed cache-line writebacks before VT-d table use.
        unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)); }
    }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (hhdm_offset, pa, bytes); }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn coherent_units_need_no_arch_cache_maintenance() { assert!(maintenance_available(true)); }
    #[test] fn x86_vtd_can_publish_noncoherent_tables() {
        assert_eq!(maintenance_available(false), cfg!(target_arch = "x86_64"));
    }
}
