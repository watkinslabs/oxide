// 431 fsconfig — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fsmount_common::*;

/// `sys_fsconfig(fd, cmd, key, value, aux)` — slot 431. Accumulates
/// options into the `fs_context`. We honour `source` via SET_STRING;
/// other keys + CMD_CREATE/RECONFIGURE are accepted.
/// # C: O(1)
pub fn sys_fsconfig(args: &SyscallArgs) -> i64 {
    const FSCONFIG_SET_STRING: u64 = 1;
    const FSCONFIG_SET_FD:     u64 = 5;
    let fd = args.a0 as i32;
    let cmd = args.a1;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.as_any().and_then(|a| a.downcast_ref::<FsContextInode>()) {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // We support no fd-valued mount options. A converted fs returns EINVAL
    // (not EOPNOTSUPP) for an unknown SET_FD key; systemd's
    // mount_option_supported() probes with a bogus SET_FD option and treats
    // success or EOPNOTSUPP as "can't determine" (-EAGAIN → log noise), but
    // EINVAL as "new mount API works, option absent" → proceeds cleanly.
    if cmd == FSCONFIG_SET_FD { return -(Errno::Einval.as_i32() as i64); }
    if cmd == FSCONFIG_SET_STRING {
        let key = read_cstr(args.a2, 64).unwrap_or_default();
        if key == "source" {
            if let Some(v) = read_cstr(args.a3, 256) {
                *ctx.source.lock() = v;
            }
        }
    }
    0
}
