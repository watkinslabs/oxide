//! CPU-transition observability.

/// Report the coordinator admission boundary before secondary CPU teardown.
/// # C: O(decimal rendering)
#[cfg(feature = "debug-hibernate")]
pub fn cpu_coordinator(cpu: u32, current: bool, idle: bool, pinned: bool) {
    klog::write_raw(b"[hibernate] cpu_coordinator cpu=");
    klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" current="); klog::write_dec_u64(current as u64);
    klog::write_raw(b" idle="); klog::write_dec_u64(idle as u64);
    klog::write_raw(b" pinned="); klog::write_dec_u64(pinned as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
/// # C: O(1)
pub fn cpu_coordinator(_: u32, _: bool, _: bool, _: bool) {}
