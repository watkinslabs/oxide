// 076 truncate — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sys_truncate(path, length)` — slot 76.
/// # C: O(N_devfs_entries)
pub fn sys_truncate(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let len      = args.a1;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped; bounded read.
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    if let Err(rv) = crate::landlock::check(s,
        ::security::landlock::access::TRUNCATE) { return rv; }
    let inode = match vfs::mount::lookup(s) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoent.as_i32() as i64),
    };
    match inode.truncate(len) { Ok(_) => 0, Err(e) => -(e as i64) }
}
