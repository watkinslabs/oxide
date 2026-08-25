#![cfg(target_os = "oxide-kernel")]

/// Scheduler diagnostics for clone publication. The macro keeps this path
/// feature-gated while the helper preserves the fields for future tracing.
pub(super) fn log_clone(parent_tid: u64, child_tid: u64, flags: u64) {
    debug_sched! {
        klog::write_raw(b"[INFO]  sys_clone: parent_tid=");
        klog::write_dec_u64(parent_tid);
        klog::write_raw(b" child_tid=");
        klog::write_dec_u64(child_tid);
        klog::write_raw(b" flags=");
        klog::write_hex_u64(flags);
        klog::write_raw(b"\n");
    }
}
