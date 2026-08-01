// 163 acct — BSD process accounting. ABI shim only: capability, path fetch,
// path resolution, and the file facts. The admission LADDER, the record format,
// the free-space hysteresis and the tunables are `fs::acct` (hosted-tested);
// the per-exit write is `acct_exit.rs`.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use ::fs::acct::{admit_file, AcctFileError, AcctFileFacts};

/// `acct(path)` — slot 163. A NULL `path` shuts accounting off; any other
/// path names the file that receives one `acct_v3` record per process exit.
///
/// Order: `CAP_SYS_PACCT` in the INITIAL user namespace FIRST (so an
/// unprivileged caller learns nothing about the path it passed), then, for a
/// non-NULL name, the write-open — whose own errno (ENOENT / ENOTDIR / ELOOP /
/// EROFS / EISDIR / EACCES) is reported verbatim — and only then the
/// accounting-specific `S_ISREG` / pseudo-filesystem / writability ladder.
/// # C: O(N_path)
pub fn sys_acct(args: &SyscallArgs) -> i64 {
    let Some(cur) = sched::live::current() else { return errno(Errno::Eperm) };
    if !crate::perm_common::capable(&cur, sched::cap::SYS_PACCT) {
        return errno(Errno::Eperm);
    }
    // Accounting is per pid namespace; `acct(2)` binds the caller's own
    // namespace, so a container cannot redirect the host's file.
    let ns_id = sched::live::pid_namespace_chain(&cur).first().copied().unwrap_or(0);
    if args.a0 == 0 {
        // Shutting accounting off succeeds whether or not it was on.
        ::fs::acct::acct_off(ns_id);
        return 0;
    }
    let path = match crate::namei_common::read_user_path(args.a0) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    // Opening for write follows the final symlink and reports its own errno
    // before any of the accounting-specific tests.
    let obj = match crate::pathresolve::resolve_path_raw(path.as_str(), false) {
        Ok(p)  => p,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    let inode = obj.inode;
    // Still part of the open, and in the open's order: taking a write reference
    // fails with EROFS on a read-only MOUNT as well as a read-only superblock;
    // then the permission test, whose EISDIR for a directory and EACCES for an
    // unwritable file are distinct answers a caller acts on differently.
    let ro = match vfs::mount::mount_by_id(obj.mnt_id) {
        Some(mnt) => vfs::mount::mnt_is_readonly(&mnt),
        None      => inode.i_sb().is_some_and(|sb| sb.is_readonly()),
    };
    if ro { return errno(Errno::Erofs); }
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = vfs::namei::may_open(&inode, false, true, &cred) {
        return crate::namei_common::errno_from_vfs(e);
    }
    match admit_file(file_facts(&inode)) {
        Ok(())                              => {}
        Err(AcctFileError::NotRegular)      => return errno(Errno::Eacces),
        Err(AcctFileError::KernelInternal)  => return errno(Errno::Einval),
        Err(AcctFileError::NotWritable)     => return errno(Errno::Eio),
    }
    ::fs::acct::acct_on(ns_id, inode, crate::acct_exit::monotonic_ns());
    0
}

/// Gather the three facts `acct_on` decides on.
/// # C: O(1)
fn file_facts(inode: &vfs::InodeRef) -> AcctFileFacts {
    let sb = inode.i_sb();
    // The superblock's kernel-internal bit plus the filesystem type's
    // user-namespace-mount restriction (procfs, sysfs) — the two-part test for
    // "this is kernel state, not a log file".
    let kernel_internal = sb.as_ref().is_some_and(|s| {
        s.s_flags() & vfs::superblock::SB_KERNMOUNT != 0
            || s.s_type.fs_flags().contains(vfs::fs::FsFlags::FS_USERNS_MOUNT_RESTRICTED)
    });
    // Does this inode's file operations table have a write path at all? A
    // zero-length write is a true no-op on every backend that HAS one, and
    // `FileOps::write`'s default returns the no-data-op errno on every backend
    // that does not — the same distinction the open draws.
    let can_write = inode.write(inode.size(), &[]).is_ok();
    AcctFileFacts {
        is_regular: matches!(inode.file_type(), vfs::FileType::Regular),
        kernel_internal,
        can_write,
    }
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }
