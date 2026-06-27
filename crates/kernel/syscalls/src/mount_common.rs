// mount_common — shared helpers for the mount-family syscalls
// (docs/53 §0). Moved verbatim from mount.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;

use syscall::errno::Errno;

/// `debug-mount`: log a mount-family syscall outcome (op label + path + rv) so
/// 226/NAMESPACE sandbox failures show the exact failing op + errno. Mount ops
/// are rare → low-volume even when enabled. No-op without the feature.
/// # C: O(len) emit when enabled
pub(crate) fn mnt_log(_op: &str, _path: &str, _rv: i64) {
    #[cfg(feature = "debug-mount")]
    {
        klog::write_raw(b"[mnt] ");
        klog::write_raw(_op.as_bytes());
        klog::write_raw(b" path=");
        klog::write_raw(_path.as_bytes());
        klog::write_raw(b" rv=");
        if _rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-_rv) as u64); }
        else { klog::write_dec_u64(_rv as u64); }
        klog::write_raw(b"\n");
    }
}

/// As `mnt_log`, plus a hex value (flags) appended after `path` and before rv.
/// # C: O(len) emit when enabled
pub(crate) fn mnt_log_hex(_op: &str, _path: &str, _flags: u64, _rv: i64) {
    #[cfg(feature = "debug-mount")]
    {
        klog::write_raw(b"[mnt] ");
        klog::write_raw(_op.as_bytes());
        klog::write_raw(b" path=");
        klog::write_raw(_path.as_bytes());
        klog::write_hex_u64(_flags);
        klog::write_raw(b" rv=");
        if _rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-_rv) as u64); }
        else { klog::write_dec_u64(_rv as u64); }
        klog::write_raw(b"\n");
    }
}

/// Read a NUL-terminated user-space C string at `p` (bounded by `max`)
/// into an owned `String`. Faults map to EFAULT, invalid UTF-8 to EINVAL.
/// # C: O(max)
pub(crate) fn read_user_cstr_owned(p: u64, max: usize) -> Result<String, i64> {
    if p == 0 || p >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p validated < USER_VA_END; bounded read via existing helper.
    let bytes = unsafe { devfs::read_user_cstr(p, max) };
    let s = bytes.and_then(|b| core::str::from_utf8(b).ok())
        .ok_or(-(Errno::Einval.as_i32() as i64))?;
    Ok(String::from(s))
}
