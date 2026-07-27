// 163 acct — BSD process accounting (Linux `kernel/acct.c
// SYSCALL_DEFINE1(acct)`). ABI shim only: capability, path fetch, path
// resolution, and the file facts. The admission LADDER and the record format
// are `fs::acct` (hosted-tested); the per-exit write is `060_exit.rs`.
//
// Slot 163 answered a blanket EPERM before F757 — a lie about the reason, and
// one no privilege could ever resolve.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use ::fs::acct::{admit_file, AcctFileError, AcctFileFacts};

/// `acct(path)` — slot 163. A NULL `path` shuts accounting off; any other
/// path names the file that receives one `acct_v3` record per process exit.
///
/// Linux order: `capable(CAP_SYS_PACCT)` FIRST (so an unprivileged caller
/// learns nothing about the path it passed), then, for a non-NULL name, the
/// open + `S_ISREG` + pseudo-filesystem + writability ladder.
/// # C: O(N_path)
pub fn sys_acct(args: &SyscallArgs) -> i64 {
    let Some(cur) = sched::live::current() else { return errno(Errno::Eperm) };
    if !crate::perm_common::capable(&cur, sched::cap::SYS_PACCT) {
        return errno(Errno::Eperm);
    }
    // Linux accounts per pid namespace (`ns->bacct`); `acct(2)` binds the
    // caller's own namespace, so a container cannot redirect the host's file.
    let ns_id = sched::live::pid_namespace_chain(&cur).first().copied().unwrap_or(0);
    if args.a0 == 0 {
        // `pin_kill(task_active_pid_ns(current)->bacct)` — succeeds whether or
        // not accounting was on.
        ::fs::acct::acct_off(ns_id);
        return 0;
    }
    let path = match crate::namei_common::read_user_path(args.a0) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    // `file_open_name(pathname, O_WRONLY|O_APPEND|O_LARGEFILE, 0)`: the lookup
    // FOLLOWS the final symlink and reports its own errno (ENOENT / ENOTDIR /
    // ELOOP / EACCES) before any of the accounting-specific tests.
    let obj = match crate::pathresolve::resolve_path_raw(path.as_str(), false) {
        Ok(p)  => p,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    let inode = obj.inode;
    // Still part of the open: a write-open of a file on a read-only mount is
    // EROFS, and one the caller may not write is EACCES.
    if let Some(sb) = inode.i_sb() {
        if sb.is_readonly() { return errno(Errno::Erofs); }
    }
    let cred = crate::pathresolve::current_cred();
    if vfs::namei::may_open(&inode, false, true, &cred).is_err() {
        return errno(Errno::Eacces);
    }
    match admit_file(file_facts(&inode)) {
        Ok(())                              => {}
        Err(AcctFileError::NotRegular)      => return errno(Errno::Eacces),
        Err(AcctFileError::KernelInternal)  => return errno(Errno::Einval),
        Err(AcctFileError::NotWritable)     => return errno(Errno::Eio),
    }
    ::fs::acct::acct_on(ns_id, inode);
    0
}

/// Gather the three facts `acct_on` decides on.
/// # C: O(1)
fn file_facts(inode: &vfs::InodeRef) -> AcctFileFacts {
    let sb = inode.i_sb();
    // `i_sb->s_flags & (SB_NOUSER | SB_KERNMOUNT)` plus the fs type's
    // `FS_USERNS_MOUNT_RESTRICTED` (procfs, sysfs) — Linux's two-part test for
    // "this is kernel state, not a log file".
    let kernel_internal = sb.as_ref().is_some_and(|s| {
        s.s_flags() & vfs::superblock::SB_KERNMOUNT != 0
            || s.s_type.fs_flags().contains(vfs::fs::FsFlags::FS_USERNS_MOUNT_RESTRICTED)
    });
    // `FMODE_CAN_WRITE`: does this inode's `f_op` have a write path at all?
    // A zero-length write is a true no-op on every backend that HAS one, and
    // `FileOps::write`'s default returns the no-data-op errno on every backend
    // that does not — the same distinction Linux draws at open time.
    let can_write = inode.write(inode.size(), &[]).is_ok();
    AcctFileFacts {
        is_regular: matches!(inode.file_type(), vfs::FileType::Regular),
        kernel_internal,
        can_write,
    }
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }
