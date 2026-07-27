// Single-arm dispatch for the credential syscall slots, so
// `syscall_glue.rs` carries one match arm instead of eighteen.

use syscall::SyscallArgs;

use super::caps::{sys_capget, sys_capset};
use super::fsid::{sys_setfsgid, sys_setfsuid};
use super::gid::{sys_getegid, sys_getgid, sys_setgid, sys_setregid, sys_setresgid};
use super::groups::{sys_getgroups, sys_setgroups};
use super::resid::{sys_getresgid, sys_getresuid};
use super::uid::{sys_geteuid, sys_getuid, sys_setresuid, sys_setreuid, sys_setuid};

/// Dispatch every cred-family syscall (`getuid`/`setuid`/etc.). Returns
/// `None` if `nr` is not a cred slot so the caller can fall through.
/// # C: O(1)
pub fn cred_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use syscall::nrs::*;
    let rv = match nr {
        NR_GETUID    => sys_getuid(args),
        NR_GETEUID   => sys_geteuid(args),
        NR_GETGID    => sys_getgid(args),
        NR_GETEGID   => sys_getegid(args),
        NR_GETRESUID => sys_getresuid(args),
        NR_GETRESGID => sys_getresgid(args),
        NR_SETUID    => sys_setuid(args),
        NR_SETGID    => sys_setgid(args),
        NR_SETREUID  => sys_setreuid(args),
        NR_SETREGID  => sys_setregid(args),
        NR_SETRESUID => sys_setresuid(args),
        NR_SETRESGID => sys_setresgid(args),
        NR_SETFSUID  => sys_setfsuid(args),
        NR_SETFSGID  => sys_setfsgid(args),
        NR_GETGROUPS => sys_getgroups(args),
        NR_SETGROUPS => sys_setgroups(args),
        NR_CAPGET    => sys_capget(args),
        NR_CAPSET    => sys_capset(args),
        _ => return None,
    };
    Some(rv)
}
