// F151 per-syscall entry trace. Gated by the `debug-syscall` cargo
// feature so call sites are absent in production builds (per
// `04§3 R05`). Used to bisect Linux-compat gaps when bringing up
// off-the-shelf userspace (busybox / coreutils / bash).
//
// Format: `[SYS] pid=<tid> nr=<dec> a0=<hex> a1=<hex> a2=<hex>`
// Three args is enough to identify the syscall; later args fall
// out of the entry log to keep line lengths bounded.

#![cfg(feature = "debug-syscall")]

/// Print one entry line for the syscall about to be dispatched.
/// # C: O(1) per call (write_raw is a UART byte-emit)
pub fn entry(nr: u64, a0: u64, a1: u64, a2: u64) {
    debug_syscall! {
        let pid = crate::sched::current().map(|t| t.tid).unwrap_or(0);
        klog::write_raw(b"[SYS] pid=");
        klog::write_dec_u64(pid as u64);
        klog::write_raw(b" nr=");
        klog::write_dec_u64(nr);
        klog::write_raw(b" a0=");
        klog::write_hex_u64(a0);
        klog::write_raw(b" a1=");
        klog::write_hex_u64(a1);
        klog::write_raw(b" a2=");
        klog::write_hex_u64(a2);
        klog::write_raw(b"\n");
    }
}
