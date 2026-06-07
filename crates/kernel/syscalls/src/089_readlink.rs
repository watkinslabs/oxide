// 089 readlink — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::userbuf::validate_user_buf;

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
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::pathresolve::resolve_cwd(raw);
    let path_s = resolved.as_str();
    // proc-link family first (/proc/self/exe etc) — not backed by Inode::readlink.
    // Otherwise resolve via the dentry walk with no_follow_final=true: Linux
    // readlink follows INTERMEDIATE symlinks in the path but returns the FINAL
    // component's link target itself (never follows it). EINVAL when the final
    // isn't a symlink (Inode::readlink errors), ENOENT when it doesn't resolve.
    let target: alloc::vec::Vec<u8> = if let Some(t) = sched::proclink::resolve_proc_link(path_s) { t }
        else if let Some(inode) = crate::pathresolve::resolve(path_s, true) {
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
