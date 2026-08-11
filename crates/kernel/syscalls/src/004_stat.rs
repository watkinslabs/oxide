// 004 stat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

use syscall::SyscallArgs;

use crate::stat_common::{STAT_BYTES, new_stat_from_kstat, write_new_stat_user};
use crate::userbuf::validate_user_buf_writable;

/// `sys_stat(path, statbuf)` / `sys_lstat(path, statbuf)` — slots 4/6.
/// Resolves `path` via the dentry path-walk and writes a per-arch struct
/// stat (x86_64 = 144 B, aarch64 asm-generic = 128 B). `follow`
/// distinguishes stat (true) from lstat (false). musl's stat()/lstat()
/// route here on x86_64 (aarch64 musl uses statx).
/// # C: O(path components × dir-lookup)
pub(crate) fn stat_impl(args: &SyscallArgs, follow: bool) -> i64 {
    let path_ptr = args.a0;
    let buf      = args.a1;

    // X2/X4/X5: PATH_MAX read; EFAULT(bad ptr) / ENOENT(empty) / ENAMETOOLONG.
    // THE resolver: one namei walk from AT_FDCWD. This preserves `cwd_vfs`
    // mount identity across fchdir/chroot/bind/pivot state instead of
    // rendering cwd to a string and re-walking a different namespace view.
    // stat(2) follows a final symlink; lstat(2) does not.
    let lf = vfs::LookupFlags {
        no_follow_final: !follow,
        follow,
        ..Default::default()
    };
    let vp = match crate::pathresolve::resolve_at_lookup(crate::pathresolve::AT_FDCWD, path_ptr, lf) {
        Ok(p)  => p,
        Err(rv) => return rv,
    };
    let inode = vp.inode;
    // vfs_getattr → i_op->getattr (default generic_fillattr): one place for
    // the S_IF* mapping + native inode metadata + idmap-out owner ids.
    let idmap = vfs::mount::idmap_for(vp.mnt_id);
    let st = vfs::vfs_getattr(&inode, &idmap);
    let dev = crate::namei_common::fsid_to_dev(st.fsid);
    let out = match new_stat_from_kstat(&st, dev) {
        Ok(o) => o,
        Err(rv) => return rv,
    };
    // Linux resolves/getattrs and converts through cp_new_stat before it faults
    // the output buffer.
    if let Err(rv) = validate_user_buf_writable(buf, STAT_BYTES, 1) { return rv; }
    if let Err(rv) = write_new_stat_user(buf, &out) { return rv; }
    0
}

/// `sys_stat(path, statbuf)` — slot 4. Follows a final symlink.
/// # C: O(path components × dir-lookup)
pub fn sys_stat(args: &SyscallArgs) -> i64 { stat_impl(args, true) }
