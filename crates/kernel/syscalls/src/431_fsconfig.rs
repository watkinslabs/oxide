// 431 fsconfig — one syscall, one file (docs/53 §0). Argument admission lives
// in `crate::fsconfig_abi`, the user-memory copy-in ORDER and its errno in
// `crate::fsconfig_fetch`; both are ungated and hosted-tested. What is left
// here is the kernel's share: the actual copy from user memory, the fd
// lookups, the capability sample and the context lock.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsconfig_abi::{self, FsconfigCmd};
use crate::fsconfig_fetch::{self, UserCopy};
use crate::fsmount_common::*;

/// `sys_fsconfig(fd, cmd, key, value, aux)` — slot 431. Accumulates options
/// into the `fs_context`. SET_FLAG/SET_STRING/SET_PATH/SET_PATH_EMPTY/
/// SET_BINARY/SET_FD all reach the filesystem through the SAME
/// `vfs_parse_fs_param` path, so a filesystem whose parameter table has no key
/// of that shape rejects it from its own parser rather than the syscall
/// refusing it blind. CMD_CREATE/CMD_CREATE_EXCL realize the tree;
/// CMD_RECONFIGURE applies parsed changes to an fspick context.
/// # C: O(1)
pub fn sys_fsconfig(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let aux = args.a4 as i32;
    let cmd = match fsconfig_abi::classify(fd, args.a1, args.a2, args.a3, aux) {
        Ok(c)  => c,
        Err(e) => return -(e.as_i32() as i64),
    };
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.private::<FsContextInode>() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };

    // Copy the key/value in from user memory FIRST — outside any fs_context
    // lock, because a user page must never be faulted while holding a spinlock.
    let fetched = match fsconfig_fetch::fetch(cmd, args.a2, args.a3, aux, &KernelUserCopy) {
        Ok(f)  => f,
        Err(e) => return -(e.as_i32() as i64),
    };
    // `param.file = fget_raw(aux)` — taken before the context lock and held
    // across the parse, so the caller closing the fd cannot free the
    // description underneath the filesystem.
    let aux_file = if cmd == FsconfigCmd::SetFd {
        match fd_file(aux) { Some(f) => Some(f), None => return -(Errno::Ebadf.as_i32() as i64) }
    } else { None };

    // `mount_capable(fc)` for the CREATE pair, sampled BEFORE the context lock
    // (the capability walk reads scheduler state). The decision itself lives in
    // `mount_dispatch::mount_capable`, the same one `mount(2)` uses, so the two
    // entry points to superblock creation cannot disagree about who may create
    // an instance of a filesystem without `FS_USERNS_MOUNT`.
    let caps = crate::mount_perm::sample_mount_caps();

    let key = &fetched.key;
    let value = &fetched.value;
    let mut g = ctx.fc.lock();
    let Some(fc) = g.as_mut() else { return -(Errno::Einval.as_i32() as i64) };
    // `finish_clean_context(fc)` heads every command.
    if let Err(e) = vfs::fs::finish_clean_context(fc) {
        return crate::namei_common::errno_from_vfs(e);
    }
    match cmd {
        FsconfigCmd::CmdCreate | FsconfigCmd::CmdCreateExcl => {
            let excl = cmd == FsconfigCmd::CmdCreateExcl;
            let can = mount_capable(fc.fs_type().fs_flags(), caps);
            match vfs::fs::vfs_cmd_create(fc, excl, can) {
                Ok(())  => 0,
                Err(e)  => crate::namei_common::errno_from_vfs(e),
            }
        }
        FsconfigCmd::CmdReconfigure => {
            // `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)`. No superblock means no
            // instance to be privileged over; the phase rung inside
            // `vfs_cmd_reconfigure` reports that case.
            let can = fc.sb().map(|sb| crate::mount_perm::cap_sys_admin_in_sb_user_ns(sb))
                .unwrap_or(false);
            match vfs::fs::vfs_cmd_reconfigure(fc, can) {
                Ok(())  => 0,
                Err(e)  => crate::namei_common::errno_from_vfs(e),
            }
        }
        FsconfigCmd::SetFlag => parse(fc, vfs::fs::FsParameter::flag(key)),
        FsconfigCmd::SetPath => parse(fc, vfs::fs::FsParameter::path_at(key, value, aux, false)),
        FsconfigCmd::SetPathEmpty => parse(fc, vfs::fs::FsParameter::path_at(key, value, aux, true)),
        FsconfigCmd::SetBinary => match &fetched.blob {
            Some(bytes) => parse(fc, vfs::fs::FsParameter::blob(key, bytes)),
            None => -(Errno::Einval.as_i32() as i64),
        },
        FsconfigCmd::SetString => parse(fc, vfs::fs::FsParameter::string(key, value)),
        FsconfigCmd::SetFd => match aux_file {
            Some(f) => parse(fc, vfs::fs::FsParameter::fd(key, aux, f)),
            None    => -(Errno::Ebadf.as_i32() as i64),
        },
    }
}

/// The kernel's bounded user-memory reads behind the ungated copy-in stage.
struct KernelUserCopy;

impl UserCopy for KernelUserCopy {
    /// # C: O(max)
    fn cstr(&self, ptr: u64, max: usize) -> Result<Vec<u8>, Errno> {
        if ptr == 0 || ptr >= hal::USER_VA_END { return Err(Errno::Efault); }
        // SAFETY: ptr checked to lie in the user range; the shared helper stops
        // at the first NUL or at `max` bytes, whichever comes first.
        unsafe { devfs::read_user_cstr(ptr, max) }.map(|b| b.to_vec()).ok_or(Errno::Efault)
    }

    /// # C: O(len)
    fn bytes(&self, ptr: u64, len: usize) -> Result<Vec<u8>, Errno> {
        let mut out = alloc::vec![0u8; len];
        uaccess::copy_from_user(&mut out, ptr).map_err(|_| Errno::Efault)?;
        Ok(out)
    }
}

/// Feed one parameter to the context (`vfs_parse_fs_param`), mapping the VFS
/// errno on a rejected/unknown option. # C: O(len key+value)
fn parse(fc: &mut vfs::fs::FsContext, param: vfs::fs::FsParameter) -> i64 {
    match vfs::fs::vfs_parse_fs_param(fc, &param) {
        Ok(())  => 0,
        Err(e)  => crate::namei_common::errno_from_vfs(e),
    }
}
