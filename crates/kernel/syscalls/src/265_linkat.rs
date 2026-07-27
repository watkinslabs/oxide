// 265 linkat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::read_user_path;

/// `linkat(odir, target, ndir, link, flags)` slot 265. Supports
/// `AT_EMPTY_PATH` (flag bit 0x1000): when set and `target` is the
/// empty string, the source is the fd in `odir`, not a path; non-empty
/// `target` still takes the normal path lookup. Supports
/// `AT_SYMLINK_FOLLOW` (0x400): the source path is dereferenced before
/// hard-linking, including Linux magic fd links such as `/proc/self/fd/N`.
/// This is how O_TMPFILE inodes get a name after creation when userspace
/// chooses the procfd route before the AT_EMPTY_PATH fallback.
/// # C: O(1)
pub fn sys_linkat(args: &SyscallArgs) -> i64 {
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    const VALID_FLAGS: u64 = AT_EMPTY_PATH | AT_SYMLINK_FOLLOW;
    let odir_fd  = args.a0 as i32;
    let target_p = args.a1;
    let link_p   = args.a3;
    let flags    = args.a4;

    if flags & !VALID_FLAGS != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }

    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let link = match read_user_path(link_p) {
        Ok(s) => s, Err(rv) => return rv,
    };

    let target_empty = if (flags & AT_EMPTY_PATH) != 0 {
        match crate::pathresolve::at_path_empty(target_p) {
            Ok(v) => v,
            Err(rv) => return rv,
        }
    } else {
        false
    };
    if target_empty {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let file = match fdt.get(odir_fd) {
            Ok(f)  => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
        };
        let cred = crate::pathresolve::current_cred();
        if !cred.cap_dac_read_search && !same_cred(file.f_cred(), &cred) {
            return -(Errno::Enoent.as_i32() as i64);
        }
        let inode = file.inode();
        return crate::s086_link::link_inode_at(inode.clone(), file.mnt_id(), args.a2 as i32, &link);
    }

    // Classic path→path linkat. With AT_SYMLINK_FOLLOW, Linux links the
    // resolved source inode instead of the symlink dentry itself.
    // D1/D2: PATH_MAX errno contract (non-AT_EMPTY_PATH path source).
    let target = match read_user_path(target_p) {
        Ok(s) => s, Err(rv) => return rv,
    };
    if (flags & AT_SYMLINK_FOLLOW) != 0 {
        // AT_SYMLINK_FOLLOW: explicitly FOLLOW the trailing symlink
        // (LOOKUP_FOLLOW) so the resolved target inode is linked.
        let lf = vfs::LookupFlags { follow: true, ..Default::default() };
        let source_inode = match crate::pathresolve::resolve_at_path(odir_fd, &target, lf) {
            Ok(p) => p, Err(rv) => return rv,
        };
        return crate::s086_link::link_inode_at(
            source_inode.inode, source_inode.mnt_id, args.a2 as i32, &link);
    }
    // vfs_link: hard-linking a directory is EPERM. Without AT_SYMLINK_FOLLOW the
    // source symlink is not followed (nofollow), matching the linked inode.
    let src = match crate::pathresolve::resolve_at_path(odir_fd, &target,
        vfs::LookupFlags { no_follow_final: true, ..Default::default() }) {
        Ok(p)  => p,
        Err(rv) => return rv,
    };
    crate::s086_link::link_inode_at(src.inode, src.mnt_id, args.a2 as i32, &link)
}

fn same_cred(a: &vfs::Cred, b: &vfs::Cred) -> bool {
    a.uid == b.uid && a.gid == b.gid
        && a.cap_dac_override == b.cap_dac_override
        && a.cap_dac_read_search == b.cap_dac_read_search
        && a.cap_fowner == b.cap_fowner
        && a.cap_chown == b.cap_chown
        && a.cap_fsetid == b.cap_fsetid
        && a.groups == b.groups
}
