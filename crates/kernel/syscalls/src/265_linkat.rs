// 265 linkat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::read_user_path;

/// `linkat(odir, target, ndir, link, flags)` slot 265. Supports
/// `AT_EMPTY_PATH` (flag bit 0x1000): when set and `target` is the
/// empty string, the source is the fd in `odir`, not a path. Supports
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

    if (flags & AT_EMPTY_PATH) != 0 {
        // target must be empty (NULL ptr or "").
        let target_empty = if target_p == 0 {
            true
        } else {
            // SAFETY: target_p in user range (we don't deref past 256B); user page mapped under caller's AS on the syscall path; bounded read.
            let bytes = unsafe { devfs::read_user_cstr(target_p, 256) };
            matches!(bytes, Some(b) if b.is_empty())
        };
        if !target_empty { return -(Errno::Einval.as_i32() as i64); }
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
        let inode = file.inode();
        return crate::s086_link::link_inode_at(inode.clone(), args.a2 as i32, &link);
    }

    // Classic path→path linkat. With AT_SYMLINK_FOLLOW, Linux links the
    // resolved source inode instead of the symlink dentry itself. `/proc/*/fd`
    // entries are magic links to open file descriptions; route them through
    // the fd table so an O_TMPFILE fd can be materialized in its own mount.
    // D1/D2: PATH_MAX errno contract (non-AT_EMPTY_PATH path source).
    let target = match read_user_path(target_p) {
        Ok(s) => s, Err(rv) => return rv,
    };
    if (flags & AT_SYMLINK_FOLLOW) != 0 {
        let t_render = crate::pathresolve::resolve_at_result(odir_fd, &target).ok();
        let source_inode = if let Some((tid_opt, fd)) = t_render.as_deref()
            .and_then(crate::open_common::parse_proc_fd) {
            match sched::proclink::proc_fd_file(tid_opt, fd) {
                Some(f) => f.inode().clone(),
                None => return -(Errno::Ebadf.as_i32() as i64),
            }
        } else {
            // AT_SYMLINK_FOLLOW: explicitly FOLLOW the trailing symlink
            // (LOOKUP_FOLLOW) so the resolved target inode is linked.
            let lf = vfs::LookupFlags { follow: true, ..Default::default() };
            match crate::pathresolve::resolve_at_path(odir_fd, &target, lf) {
                Ok(p) => p.inode,
                Err(rv) => return rv,
            }
        };
        return crate::s086_link::link_inode_at(source_inode, args.a2 as i32, &link);
    }
    // vfs_link: hard-linking a directory is EPERM. Without AT_SYMLINK_FOLLOW the
    // source symlink is not followed (nofollow), matching the linked inode.
    let src = match crate::pathresolve::resolve_at_path(odir_fd, &target,
        vfs::LookupFlags { no_follow_final: true, ..Default::default() }) {
        Ok(p)  => p.inode,
        Err(rv) => return rv,
    };
    crate::s086_link::link_inode_at(src, args.a2 as i32, &link)
}
