// F133: debug helpers for net syscalls. Split out of net.rs so
// that file stays under the 1000-line cap (`08§7`).

#![cfg(target_os = "oxide-kernel")]

/// Log ENOTSOCK + the syscall site + the failing fd's inode tag.
/// Cfg-gated under `debug-irq` so production builds emit nothing.
/// Use case: dhcpcd / systemd / NetworkManager bail with "Not a
/// socket" — flip the feature on, rerun, see exactly which
/// sys_* + fd combination is rejecting the call.
/// # C: O(1) — one fd-table lookup.
pub fn trace_enotsock_at(fd: u64, site: &'static [u8]) {
    #[cfg(feature = "debug-irq")]
    {
        klog::write_raw(b"[ENOTSOCK] site=");
        klog::write_raw(site);
        klog::write_raw(b" fd=");
        klog::write_dec_u64(fd);
        if let Some(c) = sched::live::current() {
            // SAFETY: running task on this CPU; sole reader of fd_table slot per `13§5`.
            if let Some(fdt) = unsafe { c.fd_table_ref() } {
                if let Ok(f) = fdt.get(fd as i32) {
                    klog::write_raw(b" ino=");
                    klog::write_hex_u64(f.inode().ino());
                    klog::write_raw(b" tag=");
                    klog::write_hex_u64(f.inode().ino() & 0xFFFF_FFFF_0000_0000);
                } else {
                    klog::write_raw(b" no-such-fd");
                }
            }
        }
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-irq"))]
    { let _ = (fd, site); }
}
