// 089 readlink — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_readlink(path, buf, bufsize)` — slot 89. Resolves the
/// procfs symlinks `/proc/self/{exe,cwd,root}` and per-pid
/// `/proc/<tid>/{exe,cwd,root}`. All other paths return -EINVAL.
/// # C: O(1) + O(N_tasks) for per-pid lookup
pub fn sys_readlink(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let buf_ptr  = args.a1;
    let bufsize  = args.a2;
    if bufsize == 0 { return -(Errno::Einval.as_i32() as i64); }
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let raw = path.as_str();
    let rv = readlink_at_path(crate::pathresolve::AT_FDCWD, raw, buf_ptr, bufsize);
    // Keep the plain readlink entry point in the same DRM discovery trace as
    // readlinkat: libdrm uses this form for `/sys/dev/char/<major>:<minor>`.
    #[cfg(feature = "debug-boot")]
    crate::namei_common::trace_logind_dev(b"readlink", raw, rv);
    rv
}

pub(crate) fn readlink_at_path(dirfd: i32, raw: &str, buf_ptr: u64, bufsize: u64) -> i64 {
    // DIAG (debug-syscall): the intermittent boot wedge shows a process looping
    // on readlink=-22 (EINVAL). Log the path every Nth call so the spun path is
    // symbolizable (which symlink the process wrongly sees as a non-symlink, or
    // which path it re-resolves forever).
    #[cfg(feature = "debug-syscall")]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        if N.fetch_add(1, Ordering::Relaxed) % 2000 == 0 {
            let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
            klog::write_raw(b"[RLTRACE] tid="); klog::write_dec_u64(tid as u64);
            klog::write_raw(b" path="); klog::write_raw(raw.as_bytes());
            klog::write_raw(b"\n");
        }
    }
    // Linux readlink follows intermediate symlinks in the path but returns the
    // final component's link target itself. Keep the resolved `struct path`
    // intact; procfs magic links expose their live text through Inode::get_link.
    let vp = match crate::pathresolve::resolve_at_path(dirfd, raw,
        vfs::LookupFlags { no_follow_final: true, ..Default::default() }) {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    readlink_resolved(vp, false, buf_ptr, bufsize)
}

pub(crate) fn readlink_resolved(vp: vfs::VfsPath, empty_path: bool, buf_ptr: u64, bufsize: u64) -> i64 {
    if !matches!(vp.inode.file_type(), vfs::FileType::Symlink) {
        return -((if empty_path { Errno::Enoent } else { Errno::Einval }).as_i32() as i64);
    }
    let target: alloc::vec::Vec<u8> = match vp.inode.get_link() {
        Ok(v) => v,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    write_link_target(&target, buf_ptr, bufsize)
}

/// Copy a symlink target into the caller's `buf` (truncated to `bufsize`),
/// returning the byte count — shared by `readlink`/`readlinkat`. # C: O(n)
pub(crate) fn write_link_target(target: &[u8], buf_ptr: u64, bufsize: u64) -> i64 {
    let n = (target.len() as u64).min(bufsize) as usize;
    if n != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf_ptr, n as u64, 1) { return rv; }
    }
    // SAFETY: caller validated the writable byte range; Linux readlink copyout accepts unaligned storage.
    unsafe {
        for i in 0..n {
            core::ptr::write_unaligned((buf_ptr + i as u64) as *mut u8, target[i]);
        }
    }
    n as i64
}
