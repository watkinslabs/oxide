// 079 getcwd — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

/// `sys_getcwd(buf, size)` — slot 79. Reads `current.cwd` slot.
/// Returns the path length including the trailing NUL per
/// `man 2 getcwd`; -ERANGE if `size` is too small.
/// # C: O(N_cwd)
pub fn sys_getcwd(args: &SyscallArgs) -> i64 {
    let buf  = args.a0;
    let size = args.a1;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let cwd_bytes = cur.fs_context_snapshot().cwd();
    let cwd = cwd_bytes.as_bytes();
    let need = (cwd.len() + 1) as u64;
    if size < need { return -(Errno::Erange.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(buf, need, 1) { return rv; }
    // SAFETY: exact writable user byte range validated; cwd bytes are kernel-owned.
    unsafe {
        for (i, &b) in cwd.iter().enumerate() {
            core::ptr::write_unaligned((buf + i as u64) as *mut u8, b);
        }
        core::ptr::write_unaligned((buf + cwd.len() as u64) as *mut u8, 0);
    }
    need as i64
}
