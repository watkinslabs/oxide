// sys_newfstatat — split out of `fs.rs` for the 1000-line cap.
//
// Per-arch struct stat: x86_64 = 144 B, aarch64 asm-generic = 128 B.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::stat_common::{STAT_BYTES, new_stat_from_kstat, write_new_stat_user};
use crate::userbuf::validate_user_buf_writable;

const AT_EMPTY_PATH: u32       = 0x1000;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_NO_AUTOMOUNT: u32     = 0x800;
const AT_VALID: u32 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;

/// `sys_newfstatat(dirfd, path, statbuf, flags)` — x86_64 slot 262.
/// Previously this was routed to sys_statx, which mis-reads args
/// (statx's a2=flags is newfstatat's a2=statbuf) and corrupted
/// userspace memory; the shell's PATH search on ARM printed
/// "Permission denied" for every probe.
/// # C: O(1)
pub fn sys_newfstatat(args: &SyscallArgs) -> i64 {
    let dirfd    = args.a0 as i32;
    let path_ptr = args.a1;
    let buf      = args.a2;
    let flags    = args.a3 as u32;

    // Unknown flag bits → EINVAL (Linux vfs_fstatat).
    if flags & !AT_VALID != 0 { return -(Errno::Einval.as_i32() as i64); }
    // Centralized `*at` resolution: AT_EMPTY_PATH → LOOKUP_EMPTY (empty string
    // or NULL operates on the dirfd); a normal stat FOLLOWS the
    // trailing symlink (LOOKUP_FOLLOW), AT_SYMLINK_NOFOLLOW does not. The engine
    // preserves ENOTDIR/ELOOP/EACCES/EFAULT/ENAMETOOLONG (X1/X2/X4/X5).
    let nofollow = (flags & AT_SYMLINK_NOFOLLOW) != 0;
    let lf = vfs::LookupFlags {
        empty: (flags & AT_EMPTY_PATH) != 0,
        no_follow_final: nofollow,
        follow: !nofollow,
        ..Default::default()
    };
    let (inode, mnt_id) = match crate::pathresolve::resolve_at_lookup_maybe_null(dirfd, path_ptr, lf) {
        Ok(p)  => (p.inode, p.mnt_id),
        Err(rv) => {
            #[cfg(feature = "debug-mount")]
            if let Ok(path) = crate::namei_common::read_user_path(path_ptr) {
                if path.starts_with("/run") {
                    crate::mount_common::mnt_log("newfstatat", &path, rv);
                }
            }
            return rv;
        }
    };

    // vfs_getattr → i_op->getattr: S_IF* mapping + native metadata + idmap-out.
    let idmap = vfs::mount::idmap_for(mnt_id);
    let st = vfs::vfs_getattr(&inode, &idmap);
    let dev = crate::namei_common::fsid_to_dev(st.fsid);
    let out = match new_stat_from_kstat(&st, dev) {
        Ok(o) => o,
        Err(rv) => return rv,
    };

    // Linux vfs_fstatat and cp_new_stat conversion run before the output buffer fault.
    if let Err(rv) = validate_user_buf_writable(buf, STAT_BYTES, 1) { return rv; }

    // SAFETY: buf validated STAT_BYTES writable below USER_VA_END.
    unsafe { write_new_stat_user(buf, &out); }
    0
}
