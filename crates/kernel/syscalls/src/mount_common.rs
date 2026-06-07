// mount_common — shared helpers for the mount-family syscalls
// (docs/53 §0). Moved verbatim from mount.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;

use syscall::errno::Errno;

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
