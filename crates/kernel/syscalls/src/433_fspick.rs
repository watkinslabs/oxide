// 433 fspick — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::fsmount_common::*;

/// `sys_fspick(dirfd, path, flags)` — slot 433. Opens an `fs_context` for
/// the EXISTING mount at `path` (for reconfiguration via fsconfig). The context
/// is a RECONFIGURE context bound to the picked mount's LIVE superblock + root
/// dentry (superblock D15, Linux `fs_context_for_reconfigure`), so a later
/// `fsconfig(CMD_RECONFIGURE)` actually reconfigures THAT fs in place.
/// `FSPICK_CLOEXEC = 1`.
/// # C: O(N_mounts)
pub fn sys_fspick(args: &SyscallArgs) -> i64 {
    const FSPICK_CLOEXEC: u64 = 1;
    if let Some(rv) = may_mount_or_eperm() { return rv; }  // Linux may_mount (D49)
    if args.a2 & !FSPICK_CLOEXEC != 0 { return -(Errno::Einval.as_i32() as i64); }
    let path = match read_cstr_req(args.a1, 256) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let picked = match crate::pathresolve::resolve_path_raw(&path, false) {
        Ok(p) => p,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    let mnt = match vfs::mount::mount_by_id(picked.mnt_id) {
        Some(m) => m, None => return -(Errno::Enoent.as_i32() as i64),
    };
    // Bind a FOR_RECONFIGURE context to the picked mount's live SB + root dentry.
    // Seed `sb_flags` with the SB's CURRENT user-settable bits (Linux fspick seeds
    // `dentry->d_sb->s_flags`) so a RECONFIGURE with no flag delta is a no-op and a
    // later "ro"/"rw" toggle re-applies cleanly; the mask is `SB_FLAGS_USER_MASK`.
    let sb = mnt.sb().clone();
    let root = match mnt.mnt_root() {
        Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
    };
    let sb_flags = sb.s_flags();
    let fc = vfs::fs::FsContext::for_reconfigure(sb, root, sb_flags, vfs::fs::SB_FLAGS_USER_MASK);
    let inode: InodeRef = FsContextInode::new_reconfigure(mnt.sb().s_type.name().to_string(), fc);
    install_fd(inode, "[fscontext]", (args.a2 & FSPICK_CLOEXEC) != 0)
}
