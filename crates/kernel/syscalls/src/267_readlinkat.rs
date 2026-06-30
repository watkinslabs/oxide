// 267 readlinkat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

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
    if bufsize == 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf_writable(buf_ptr, bufsize, 1) {
        return rv;
    }
    // D1/D2: PATH_MAX errno contract via read_user_path (EFAULT/ENAMETOOLONG).
    // D20: readlinkat passes LOOKUP_EMPTY (since Linux 2.6.39): an empty pathname
    // (read_user_path → ENOENT) operates on `dirfd` itself — read its own symlink
    // target. NULL ptr → EFAULT (getname), preserved by read_user_path.
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s) => s,
        Err(rv) if rv == -(Errno::Enoent.as_i32() as i64) =>
            return readlinkat_empty(dirfd, buf_ptr, bufsize),
        Err(rv) => return rv,
    };
    let raw: &str = path.as_str();
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
