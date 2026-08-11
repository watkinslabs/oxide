// 079 getcwd — one syscall, one file (docs/53 §0). ABI shim only: the pwd is
// rendered by `fs::cwd::getcwd_path`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;
use crate::user_mem as um;

/// `sys_getcwd(buf, size)` — slot 79. Returns the path length INCLUDING the
/// trailing NUL (Linux returns `len` where `len` counts the NUL it prepended);
/// `ERANGE` when `size` cannot hold it, checked before the copy-out so a short
/// buffer is never partially written.
/// # C: O(depth)
pub fn sys_getcwd(args: &SyscallArgs) -> i64 {
    let buf  = args.a0;
    let size = args.a1;
    let cwd = match ::fs::cwd::getcwd_path() { Ok(s) => s, Err(rv) => return rv };
    let bytes = cwd.as_bytes();
    let need = (bytes.len() + 1) as u64;
    if size < need { return -(Errno::Erange.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(buf, need, 1) { return rv; }
    if um::put_bytes(buf, bytes).is_err() { return um::EFAULT; }
    if um::put_u8(buf + bytes.len() as u64, 0).is_err() { return um::EFAULT; }
    need as i64
}
