// chmod/chown family dispatch arm. Per docs/53 §0 each handler now lives
// in its own per-syscall file (090_chmod, 091_fchmod, 268_fchmodat,
// 092_chown, 093_fchown, 260_fchownat); shared resolver helpers + AT_*
// consts live in perms_common.rs. This file retains only the single-arm
// dispatch helper consumed by dispatch.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// Single-arm dispatch helper for syscall_glue.rs.
/// # C: O(1)
pub fn perms_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use syscall::nrs::*;
    let rv = match nr {
        NR_CHMOD     => crate::s090_chmod::sys_chmod(args),
        NR_FCHMOD    => crate::s091_fchmod::sys_fchmod(args),
        NR_FCHMODAT  => crate::s268_fchmodat::sys_fchmodat(args),
        // Distinct slots: `chown` FOLLOWS the final symlink, `lchown` does not
        // (Linux `do_fchownat(..., AT_SYMLINK_NOFOLLOW)`).
        NR_CHOWN     => crate::s092_chown::sys_chown(args),
        NR_LCHOWN    => crate::s094_lchown::sys_lchown(args),
        NR_FCHOWN    => crate::s093_fchown::sys_fchown(args),
        NR_FCHOWNAT  => crate::s260_fchownat::sys_fchownat(args),
        _ => return None,
    };
    Some(rv)
}
