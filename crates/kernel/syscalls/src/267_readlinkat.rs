// 267 readlinkat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_readlinkat(dirfd, path, buf, bufsize)` — slot 267.
/// Resolves relative paths against `dirfd`, then returns the final symlink's
/// literal target without following it.
/// # C: O(1)
pub fn sys_readlinkat(args: &SyscallArgs) -> i64 {
    let dirfd = args.a0 as i32;
    let path_ptr = args.a1;
    let buf_ptr = args.a2;
    // `do_readlinkat`'s signed `bufsiz`: zero and negative are both EINVAL.
    let bufsiz = args.a3 as i32;
    if let Err(e) = crate::path_ops_policy::check_readlink_bufsiz(bufsiz) {
        return -(e.as_i32() as i64);
    }
    let bufsize = bufsiz as u64;
    let empty = match crate::pathresolve::at_path_empty(path_ptr) {
        Ok(v) => v,
        Err(rv) => return rv,
    };
    // D20: readlinkat uses LOOKUP_EMPTY. Empty pathname operates on dirfd
    // itself; non-symlink empty results are ENOENT, not EINVAL.
    if empty { return readlinkat_lookup(dirfd, path_ptr, true, buf_ptr, bufsize); }
    let path = match crate::namei_common::read_user_path(path_ptr) { Ok(s) => s, Err(rv) => return rv };
    let raw: &str = path.as_str();
    let rv = crate::s089_readlink::readlink_at_path(dirfd, raw, buf_ptr, bufsize);
    #[cfg(feature = "debug-desktop")]
    crate::namei_common::trace_logind_dev(b"readlink", raw, rv);
    rv
}

/// Resolve via LOOKUP_EMPTY, preserving Linux's empty-path non-symlink ENOENT.
/// # C: O(components × dir-lookup) + O(symlinks)
fn readlinkat_lookup(dirfd: i32, path_ptr: u64, empty: bool, buf_ptr: u64, bufsize: u64) -> i64 {
    let vp = match crate::pathresolve::resolve_at_lookup(dirfd, path_ptr,
        vfs::LookupFlags { empty, no_follow_final: true, follow: false, ..Default::default() }) {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    crate::s089_readlink::readlink_resolved(vp, empty, buf_ptr, bufsize)
}
