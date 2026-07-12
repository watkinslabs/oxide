// 431 fsconfig — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsmount_common::*;

/// `sys_fsconfig(fd, cmd, key, value, aux)` — slot 431. Accumulates options
/// into the `fs_context` per the Linux command set. SET_FLAG/SET_STRING/
/// SET_PATH/SET_PATH_EMPTY/SET_BINARY store the key/value; `source` is mirrored
/// into the context source. SET_FD → EINVAL (no fd-valued options supported).
/// CMD_CREATE/CMD_CREATE_EXCL realize the tree; CMD_RECONFIGURE applies parsed
/// changes to an fspick context. An unknown command is EINVAL (Linux
/// `vfs_fsconfig_locked`).
/// # C: O(1)
pub fn sys_fsconfig(args: &SyscallArgs) -> i64 {
    const FSCONFIG_SET_FLAG:       u64 = 0;
    const FSCONFIG_SET_STRING:     u64 = 1;
    const FSCONFIG_SET_BINARY:     u64 = 2;
    const FSCONFIG_SET_PATH:       u64 = 3;
    const FSCONFIG_SET_PATH_EMPTY: u64 = 4;
    const FSCONFIG_SET_FD:         u64 = 5;
    const FSCONFIG_CMD_CREATE:      u64 = 6;
    const FSCONFIG_CMD_RECONFIGURE: u64 = 7;
    const FSCONFIG_CMD_CREATE_EXCL: u64 = 8;
    let fd = args.a0 as i32;
    let cmd = args.a1;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.private::<FsContextInode>() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };

    // Read the option key/value from user memory FIRST (outside any fs_context
    // lock — never fault a user page while holding a spinlock); a SET_* command
    // needs a non-empty key (Linux requires `key` for everything but CMD_*).
    let is_param = matches!(cmd, FSCONFIG_SET_FLAG | FSCONFIG_SET_STRING
        | FSCONFIG_SET_BINARY | FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY);
    let (key, value) = if is_param {
        let key = match read_cstr_req(args.a2, 64) {
            Ok(k) if !k.is_empty() => k,
            Ok(_) => return -(Errno::Einval.as_i32() as i64),
            Err(rv) => return rv,
        };
        let value = if cmd == FSCONFIG_SET_FLAG { alloc::string::String::new() }
            else if cmd == FSCONFIG_SET_PATH || cmd == FSCONFIG_SET_PATH_EMPTY {
                match read_path_allow_empty(args.a3) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            } else {
                match read_cstr_req(args.a3, 256) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            };
        (key, value)
    } else {
        (alloc::string::String::new(), alloc::string::String::new())
    };

    // CONVERTED pseudo fstype: thread the command through the real
    // `vfs::fs::FsContext` (D14: params no longer dropped; D13: SB realized at
    // CMD_CREATE; D15: CMD_RECONFIGURE). SET_FD stays EINVAL (systemd's
    // mount_option_supported() probe). An unrecognised parameter / parse error
    // surfaces the VFS errno.
    {
        let mut g = ctx.fc.lock();
        if let Some(fc) = g.as_mut() {
            return match cmd {
                FSCONFIG_SET_FD => -(Errno::Einval.as_i32() as i64),
                FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => match vfs::fs::vfs_get_tree(fc) {
                    Ok(())  => 0,
                    Err(e)  => crate::namei_common::errno_from_vfs(e),
                },
                FSCONFIG_CMD_RECONFIGURE => match vfs::fs::reconfigure_super(fc) {
                    Ok(())  => 0,
                    Err(e)  => crate::namei_common::errno_from_vfs(e),
                },
                FSCONFIG_SET_FLAG => parse(fc, vfs::fs::FsParameter::flag(&key)),
                FSCONFIG_SET_PATH => parse(fc, vfs::fs::FsParameter::path(&key, &value)),
                FSCONFIG_SET_PATH_EMPTY => parse(fc, vfs::fs::FsParameter::path_empty(&key, &value)),
                FSCONFIG_SET_BINARY => parse(fc, vfs::fs::FsParameter::blob(&key, value.as_bytes())),
                FSCONFIG_SET_STRING => parse(fc, vfs::fs::FsParameter::string(&key, &value)),
                _ => -(Errno::Einval.as_i32() as i64),
            };
        }
    }

    -(Errno::Einval.as_i32() as i64)
}

/// Feed one parameter to the context (`vfs_parse_fs_param`), mapping the VFS
/// errno on a rejected/unknown option. # C: O(len key+value)
fn parse(fc: &mut vfs::fs::FsContext, param: vfs::fs::FsParameter) -> i64 {
    match vfs::fs::vfs_parse_fs_param(fc, &param) {
        Ok(())  => 0,
        Err(e)  => crate::namei_common::errno_from_vfs(e),
    }
}
