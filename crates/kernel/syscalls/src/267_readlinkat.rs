// 267 readlinkat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::userbuf::validate_user_buf_writable;

/// `sys_readlinkat(dirfd, path, buf, bufsize)` — slot 267.
/// Resolves relative paths against `dirfd`, then returns the final symlink's
/// literal target without following it.
/// # C: O(1)
pub fn sys_readlinkat(args: &SyscallArgs) -> i64 {
    let dirfd = args.a0 as i32;
    let path_ptr = args.a1;
    let buf_ptr = args.a2;
    let bufsize = args.a3;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if bufsize == 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf_writable(buf_ptr, bufsize, 1) {
        return rv;
    }
    // SAFETY: ptr in user range; bounded C-string read.
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        // D20: readlinkat passes LOOKUP_EMPTY (since Linux 2.6.39): an empty
        // pathname operates on `dirfd` itself — read its own symlink target.
        // `dirfd` must be a real O_PATH|O_NOFOLLOW fd to a symlink; AT_FDCWD
        // has no fd, and cwd is a directory (EINVAL on readlink of a non-link).
        _ => return readlinkat_empty(dirfd, buf_ptr, bufsize),
    };
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = match crate::pathresolve::resolve_at_result(dirfd, raw) {
        Ok(s) => s,
        Err(rv) => return rv,
    };
    crate::s089_readlink::readlink_resolved_path(resolved.as_str(), buf_ptr, bufsize)
}

/// D20: empty-path `readlinkat` — operate on `dirfd` itself (LOOKUP_EMPTY).
/// Returns the fd's own symlink target, or EINVAL when the fd is not a symlink
/// (Linux `->readlink` is only set on symlink inodes). # C: O(1)
fn readlinkat_empty(dirfd: i32, buf_ptr: u64, bufsize: u64) -> i64 {
    let f = match crate::perms_common::resolve_fd_file(dirfd) { Ok(f) => f, Err(rv) => return rv };
    let inode = f.inode();
    if !matches!(inode.file_type(), vfs::FileType::Symlink) {
        return -(Errno::Einval.as_i32() as i64);
    }
    match inode.get_link() {
        Ok(target) => crate::s089_readlink::write_link_target(&target, buf_ptr, bufsize),
        Err(_)     => -(Errno::Einval.as_i32() as i64),
    }
}
