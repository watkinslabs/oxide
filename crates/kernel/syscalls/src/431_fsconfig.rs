// 431 fsconfig — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsmount_common::*;

/// `sys_fsconfig(fd, cmd, key, value, aux)` — slot 431. Accumulates options
/// into the `fs_context` per the Linux command set. SET_FLAG/SET_STRING/
/// SET_PATH/SET_PATH_EMPTY/SET_BINARY store the key/value; `source` is mirrored
/// into the context source. SET_FD → EINVAL (no fd-valued options supported).
/// CMD_CREATE/CMD_RECONFIGURE/CMD_CREATE_EXCL are accepted (materialisation is
/// deferred to fsmount). An unknown command is EINVAL (Linux `vfs_fsconfig_locked`).
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
    match cmd {
        // We support no fd-valued mount options. A converted fs returns EINVAL
        // (not EOPNOTSUPP) for an unknown SET_FD key; systemd's
        // mount_option_supported() probes with a bogus SET_FD option and treats
        // EINVAL as "new mount API works, option absent" → proceeds cleanly.
        FSCONFIG_SET_FD => -(Errno::Einval.as_i32() as i64),
        // Action commands: no key/value; materialisation happens at fsmount.
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_RECONFIGURE | FSCONFIG_CMD_CREATE_EXCL => 0,
        FSCONFIG_SET_FLAG | FSCONFIG_SET_STRING | FSCONFIG_SET_BINARY
        | FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            // A NULL/empty key is invalid for a parameter command (Linux requires
            // `key` for everything but the CMD_* actions).
            let key = match read_cstr(args.a2, 64) {
                Some(k) if !k.is_empty() => k,
                _ => return -(Errno::Einval.as_i32() as i64),
            };
            // SET_FLAG carries no value; the rest read a textual value (path /
            // string / binary blob rendered as bytes-as-str).
            let value = if cmd == FSCONFIG_SET_FLAG {
                alloc::string::String::new()
            } else {
                read_cstr(args.a3, 256).unwrap_or_default()
            };
            if key == "source" { *ctx.source.lock() = value.clone(); }
            ctx.options.lock().push((key, value));
            0
        }
        // Unknown command → EINVAL (Linux vfs_fsconfig_locked default).
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
