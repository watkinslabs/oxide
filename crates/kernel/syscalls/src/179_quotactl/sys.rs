use syscall::{errno::Errno, SyscallArgs};

use super::{cmd::*, dispatch, eno};

/// `sys_quotactl(cmd, special, id, addr)` target selection. # C: O(path)+O(N_sb)+FS
pub fn sys_quotactl(args: &SyscallArgs) -> i64 {
    let cmd = args.a0 as u32 as u64;
    let subcmd = cmd >> SUBCMD_SHIFT;
    if !quotactl_cmd_type_valid(cmd) { return eno(Errno::Einval); }
    if args.a1 == 0 {
        if subcmd == Q_SYNC { return dispatch::quotactl_dispatch(cmd); }
        return eno(Errno::Enodev);
    }
    let quotaon_path = if subcmd == Q_QUOTAON {
        dispatch::resolve_quotaon_path(args.a3).map(Some)
    } else {
        Ok(None)
    };
    let raw = match crate::namei_common::read_user_path(args.a1) { Ok(p) => p, Err(rv) => return rv };
    let path = match crate::pathresolve::resolve_path_raw(&raw, true) {
        Ok(p) => p,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    if path.inode.file_type() != vfs::FileType::BlockDev { return eno(Errno::Enotblk); }
    let sb = match vfs::superblock::sb_by_dev(path.inode.rdev() as u64) {
        Some(sb) => sb,
        None => return eno(Errno::Enodev),
    };
    let quotaon_ref = match quotaon_path.as_ref() {
        Ok(Some(p)) => Ok(Some(p)),
        Ok(None) => Ok(None),
        Err(rv) => Err(*rv),
    };
    dispatch::quotactl_dispatch_sb_block(&sb, cmd, args.a2, args.a3, quotaon_ref)
}
