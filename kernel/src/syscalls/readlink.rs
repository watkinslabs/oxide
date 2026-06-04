// readlink / readlinkat — split out of `fs.rs` for the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::syscalls::validate_user_buf;

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
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if bufsize == 0 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(buf_ptr, bufsize, 1) { return rv; }
    // SAFETY: ptr in user range; user page mapped (caller already executed user code from this AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::syscalls::pathresolve::resolve_cwd(raw);
    readlink_write(resolved.as_str(), buf_ptr, bufsize)
}

/// Shared readlink body: resolve `path_s` (already absolute) to a link
/// target and copy ≤`bufsize` bytes to `buf_ptr`. proc-link family first
/// (`/proc/self/exe` etc — not backed by `Inode::readlink`); otherwise
/// dentry walk with no-follow-final (Linux follows intermediate symlinks
/// but returns the final component's link target). EINVAL when the final
/// isn't a symlink, ENOENT when it doesn't resolve.
/// # C: O(N_path) + O(target_len)
fn readlink_write(path_s: &str, buf_ptr: u64, bufsize: u64) -> i64 {
    let target: alloc::vec::Vec<u8> = if let Some(t) = sched::proclink::resolve_proc_link(path_s) { t }
        else if let Some(inode) = crate::syscalls::pathresolve::resolve(path_s, true) {
            match inode.readlink() { Ok(v) => v, Err(_) => return -(Errno::Einval.as_i32() as i64) }
        } else { return -(Errno::Enoent.as_i32() as i64); };
    let n = (target.len() as u64).min(bufsize) as usize;
    // SAFETY: buf range validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for i in 0..n {
            core::ptr::write_volatile((buf_ptr + i as u64) as *mut u8, target[i]);
        }
    }
    n as i64
}

/// `sys_readlinkat(dirfd, path, buf, bufsize)` — slot 267. Honours
/// `dirfd` (absolute / AT_FDCWD / real dirfd) so a relative link probe
/// against an open directory fd resolves correctly.
/// # C: O(N_path)
pub fn sys_readlinkat(args: &SyscallArgs) -> i64 {
    let dirfd    = args.a0 as i32;
    let path_ptr = args.a1;
    let buf_ptr  = args.a2;
    let bufsize  = args.a3;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if bufsize == 0 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(buf_ptr, bufsize, 1) { return rv; }
    let resolved = match crate::syscalls::pathresolve::resolve_at_user(dirfd, path_ptr) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    readlink_write(resolved.as_str(), buf_ptr, bufsize)
}
