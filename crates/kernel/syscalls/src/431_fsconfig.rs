// 431 fsconfig — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsconfig_abi::{self, FsconfigCmd, ValueKind};
use crate::fsmount_common::*;

/// `sys_fsconfig(fd, cmd, key, value, aux)` — slot 431. Accumulates options
/// into the `fs_context` per the Linux command set. SET_FLAG/SET_STRING/
/// SET_PATH/SET_PATH_EMPTY/SET_BINARY store the key/value; `source` is mirrored
/// into the context source. SET_FD pins `aux`'s open file (`fget_raw`) and
/// hands the filesystem an `fs_value_is_file` parameter through the SAME
/// `vfs_parse_fs_param` path the other SET_* commands use, so an fs whose
/// parameter spec has no fd-typed key rejects it from its own parser (Linux
/// `legacy_parse_param`) instead of the syscall refusing it blind.
/// CMD_CREATE/CMD_CREATE_EXCL realize the tree; CMD_RECONFIGURE applies parsed
/// changes to an fspick context. Argument admission and the EOPNOTSUPP for an
/// unknown command live in `fsconfig_abi::classify`.
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

    // Copy the option key/value in from user memory FIRST (outside any
    // fs_context lock — never fault a user page while holding a spinlock).
    // An empty key is left for `vfs_parse_fs_param` to reject, which is where
    // Linux reports it ("VFS: Empty parameter name").
    let key = if cmd.takes_key() {
        match read_cstr_req(args.a2, fsconfig_abi::KEY_MAX) { Ok(k) => k, Err(rv) => return rv }
    } else { alloc::string::String::new() };
    let value = match cmd.value_kind() {
        ValueKind::None => alloc::string::String::new(),
        ValueKind::Path { .. } => match read_path_allow_empty(args.a3) { Ok(v) => v, Err(rv) => return rv },
        ValueKind::Str | ValueKind::Blob => match read_cstr_req(args.a3, fsconfig_abi::VALUE_MAX) {
            Ok(v) => v, Err(rv) => return rv,
        },
    };
    // `param.file = fget_raw(aux); if (!param.file) ret = -EBADF;` — taken
    // before the context lock and held across the parse, so the caller closing
    // the fd cannot free the description underneath the filesystem.
    let aux_file = if cmd == FsconfigCmd::SetFd {
        match fd_file(aux) { Some(f) => Some(f), None => return -(Errno::Ebadf.as_i32() as i64) }
    } else { None };

    // CONVERTED pseudo fstype: thread the command through the real
    // `vfs::fs::FsContext` (D14: params no longer dropped; D13: SB realized at
    // CMD_CREATE; D15: CMD_RECONFIGURE). An unrecognised parameter / parse
    // error surfaces the VFS errno.
    {
        let mut g = ctx.fc.lock();
        if let Some(fc) = g.as_mut() {
            return match cmd {
                FsconfigCmd::CmdCreate | FsconfigCmd::CmdCreateExcl => match vfs::fs::vfs_get_tree(fc) {
                    Ok(())  => 0,
                    Err(e)  => crate::namei_common::errno_from_vfs(e),
                },
                FsconfigCmd::CmdReconfigure => match vfs::fs::reconfigure_super(fc) {
                    Ok(())  => 0,
                    Err(e)  => crate::namei_common::errno_from_vfs(e),
                },
                FsconfigCmd::SetFlag => parse(fc, vfs::fs::FsParameter::flag(&key)),
                FsconfigCmd::SetPath => parse(fc, vfs::fs::FsParameter::path(&key, &value)),
                FsconfigCmd::SetPathEmpty => parse(fc, vfs::fs::FsParameter::path_empty(&key, &value)),
                FsconfigCmd::SetBinary => parse(fc, vfs::fs::FsParameter::blob(&key, value.as_bytes())),
                FsconfigCmd::SetString => parse(fc, vfs::fs::FsParameter::string(&key, &value)),
                FsconfigCmd::SetFd => match aux_file {
                    Some(f) => parse(fc, vfs::fs::FsParameter::fd(&key, aux, f)),
                    None    => -(Errno::Ebadf.as_i32() as i64),
                },
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
