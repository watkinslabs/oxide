//! Per-exec provenance for diagnosing initial userspace handoff.

/// Emit the exact main-image metadata handed to the ELF interpreter.
///
/// This is intentionally feature-gated: it correlates a later page fault with
/// the one `execve` that constructed the task's auxv and return frame.
#[cfg(feature = "debug-execload")]
pub(super) fn ready(
    tid: u32,
    root: u64,
    entry: u64,
    phdr: u64,
    interp_base: u64,
    stack: u64,
) {
    klog::write_raw(b"[EXECLOAD ready tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" root=");
    klog::write_hex_u64(root);
    klog::write_raw(b" entry=");
    klog::write_hex_u64(entry);
    klog::write_raw(b" phdr=");
    klog::write_hex_u64(phdr);
    klog::write_raw(b" base=");
    klog::write_hex_u64(interp_base);
    klog::write_raw(b" sp=");
    klog::write_hex_u64(stack);
    klog::write_raw(b"]\n");
}
