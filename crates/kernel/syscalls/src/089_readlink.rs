// 089 readlink — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

/// `sys_readlink(path, buf, bufsize)` — slot 89. Resolves the
/// procfs symlinks `/proc/self/{exe,cwd,root}` and per-pid
/// `/proc/<tid>/{exe,cwd,root}`. `exe` reports argv[0] from the
/// task's cmdline snapshot (`/init` when unset). All other paths
/// return -EINVAL.
/// # C: O(1) + O(N_tasks) for per-pid lookup
pub fn sys_readlink(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let buf_ptr  = args.a1;
    let bufsize  = args.a2;
    if bufsize == 0 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(buf_ptr, bufsize, 1) { return rv; }
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let raw: &str = path.as_str();
    let resolved = crate::pathresolve::resolve_cwd(raw);
    readlink_resolved_path(resolved.as_str(), buf_ptr, bufsize)
}

pub(crate) fn readlink_resolved_path(path_s: &str, buf_ptr: u64, bufsize: u64) -> i64 {
    // proc-link family first (/proc/self/exe etc) — not backed by Inode::readlink.
    // Otherwise resolve via the dentry walk with no_follow_final=true: Linux
    // readlink follows INTERMEDIATE symlinks in the path but returns the FINAL
    // component's link target itself (never follows it). EINVAL when the final
    // isn't a symlink (Inode::readlink errors), ENOENT when it doesn't resolve.
    let target: alloc::vec::Vec<u8> = if let Some(t) = sched::proclink::resolve_proc_link(path_s) { t }
        else if let Some(inode) = crate::pathresolve::resolve(path_s, true) {
            match inode.get_link() { Ok(v) => v, Err(_) => return -(Errno::Einval.as_i32() as i64) }
        } else { return -(Errno::Enoent.as_i32() as i64); };
    write_link_target(&target, buf_ptr, bufsize)
}

/// Copy a symlink target into the caller's `buf` (truncated to `bufsize`),
/// returning the byte count — shared by `readlink`/`readlinkat`. # C: O(n)
pub(crate) fn write_link_target(target: &[u8], buf_ptr: u64, bufsize: u64) -> i64 {
    let n = (target.len() as u64).min(bufsize) as usize;
    // SAFETY: buf range validated < USER_VA_END by the caller; CPL=0 writes through caller's AS.
    unsafe {
        for i in 0..n {
            core::ptr::write_volatile((buf_ptr + i as u64) as *mut u8, target[i]);
        }
    }
    n as i64
}
