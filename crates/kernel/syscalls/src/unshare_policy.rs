// unshare(2) flag contract — Linux `kernel/fork.c` (`ksys_unshare`,
// `check_unshare_flags`) and `kernel/nsproxy.c`
// (`unshare_nsproxy_namespaces`).
//
// Kept OUTSIDE the `target_os = "oxide-kernel"` gate: the implied-flag
// expansion, the EINVAL ladder and "which capability does this flag set need"
// are pure, and they are the whole observable contract of a rejected call
// (`CLAUDE.md` "Verify left"). `272_unshare.rs` owns only the state mutation.

use syscall::errno::Errno;

pub const CLONE_NEWTIME:  u64 = 0x0000_0080;
pub const CLONE_VM:       u64 = 0x0000_0100;
pub const CLONE_FS:       u64 = 0x0000_0200;
pub const CLONE_FILES:    u64 = 0x0000_0400;
pub const CLONE_SIGHAND:  u64 = 0x0000_0800;
pub const CLONE_THREAD:   u64 = 0x0001_0000;
pub const CLONE_NEWNS:    u64 = 0x0002_0000;
pub const CLONE_SYSVSEM:  u64 = 0x0004_0000;
/// Linux `UNSHARE_EMPTY_MNTNS` (`include/uapi/linux/sched.h`) — aliases
/// `CLONE_PARENT_SETTID` in the 32-bit unshare flag word.
pub const UNSHARE_EMPTY_MNTNS: u64 = 0x0010_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS:   u64 = 0x0400_0000;
pub const CLONE_NEWIPC:   u64 = 0x0800_0000;
pub const CLONE_NEWUSER:  u64 = 0x1000_0000;
pub const CLONE_NEWPID:   u64 = 0x2000_0000;
pub const CLONE_NEWNET:   u64 = 0x4000_0000;

/// Linux `CLONE_NS_ALL` — every `CLONE_NEW*` namespace bit.
pub const CLONE_NS_ALL: u64 = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC
    | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWTIME;

/// The exact set `check_unshare_flags` tolerates.
pub const UNSHARE_ALLOWED: u64 = CLONE_THREAD | CLONE_FS | CLONE_SIGHAND | CLONE_VM
    | CLONE_FILES | CLONE_SYSVSEM | CLONE_NS_ALL | UNSHARE_EMPTY_MNTNS;

/// `ksys_unshare`'s implied-flag expansion, run BEFORE `check_unshare_flags`
/// so the implied bits are themselves validated:
///
/// ```text
/// if (unshare_flags & CLONE_NEWUSER)         unshare_flags |= CLONE_THREAD | CLONE_FS;
/// if (unshare_flags & CLONE_VM)              unshare_flags |= CLONE_SIGHAND;
/// if (unshare_flags & CLONE_SIGHAND)         unshare_flags |= CLONE_THREAD;
/// if (unshare_flags & UNSHARE_EMPTY_MNTNS)   unshare_flags |= CLONE_NEWNS;
/// if (unshare_flags & CLONE_NEWNS)           unshare_flags |= CLONE_FS;
/// ```
///
/// The `CLONE_NEWUSER -> CLONE_THREAD` implication is why `unshare(
/// CLONE_NEWUSER)` from a multi-threaded process is EINVAL.
/// # C: O(1)
pub fn expand_implied(mut flags: u64) -> u64 {
    if (flags & CLONE_NEWUSER) != 0 { flags |= CLONE_THREAD | CLONE_FS; }
    if (flags & CLONE_VM) != 0 { flags |= CLONE_SIGHAND; }
    if (flags & CLONE_SIGHAND) != 0 { flags |= CLONE_THREAD; }
    if (flags & UNSHARE_EMPTY_MNTNS) != 0 { flags |= CLONE_NEWNS; }
    if (flags & CLONE_NEWNS) != 0 { flags |= CLONE_FS; }
    flags
}

/// Linux `check_unshare_flags`, over already-expanded flags:
///
/// ```text
/// if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_SIGHAND|CLONE_VM|
///                       CLONE_FILES|CLONE_SYSVSEM|CLONE_NS_ALL|
///                       UNSHARE_EMPTY_MNTNS))                    return -EINVAL;
/// if (unshare_flags & (CLONE_THREAD|CLONE_SIGHAND|CLONE_VM))
///         if (!thread_group_empty(current))                      return -EINVAL;
/// if (unshare_flags & (CLONE_SIGHAND|CLONE_VM))
///         if (refcount_read(&current->sighand->count) > 1)       return -EINVAL;
/// if (unshare_flags & CLONE_VM)
///         if (!current_is_single_threaded())                     return -EINVAL;
/// ```
///
/// CLONE_THREAD / CLONE_SIGHAND / CLONE_VM are NOT rejected outright — Linux
/// accepts them as no-ops when there is nothing to unshare ("pretend it works
/// if there is nothing to unshare"), and rejects them only when the caller is
/// multi-threaded or shares a `sighand_struct`.
/// # C: O(1)
pub fn check_unshare_flags(flags: u64, thread_group_single: bool, sighand_shared: bool)
    -> Result<(), Errno>
{
    if (flags & !UNSHARE_ALLOWED) != 0 { return Err(Errno::Einval); }
    if (flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM)) != 0 && !thread_group_single {
        return Err(Errno::Einval);
    }
    if (flags & (CLONE_SIGHAND | CLONE_VM)) != 0 && sighand_shared {
        return Err(Errno::Einval);
    }
    if (flags & CLONE_VM) != 0 && !thread_group_single { return Err(Errno::Einval); }
    Ok(())
}

/// Linux `unshare_nsproxy_namespaces`: a single `ns_capable(user_ns,
/// CAP_SYS_ADMIN)` guards the WHOLE namespace set, and is skipped when only
/// `CLONE_NEWUSER` was requested (`CLONE_NS_ALL & ~CLONE_NEWUSER`) — creating a
/// user namespace is itself unprivileged. `user_ns` is the NEW user namespace
/// when `CLONE_NEWUSER` is in the set, which is what lets a rootless caller
/// stack `CLONE_NEWUSER | CLONE_NEWNS` in one call.
/// # C: O(1)
pub fn needs_sys_admin(flags: u64) -> bool { (flags & (CLONE_NS_ALL & !CLONE_NEWUSER)) != 0 }

/// `CLONE_SYSVSEM` and `CLONE_NEWIPC` both detach the caller from its SysV
/// semaphore undo list — Linux runs `exit_sem(current)` for either, because a
/// task that moved to a new IPC namespace can no longer reach the arrays its
/// undo entries name. # C: O(1)
pub fn detaches_sysvsem(flags: u64) -> bool { (flags & (CLONE_NEWIPC | CLONE_SYSVSEM)) != 0 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newuser_implies_thread_and_fs() {
        let f = expand_implied(CLONE_NEWUSER);
        assert_ne!(f & CLONE_THREAD, 0);
        assert_ne!(f & CLONE_FS, 0);
    }

    #[test]
    fn newns_implies_fs_and_empty_mntns_implies_newns() {
        assert_ne!(expand_implied(CLONE_NEWNS) & CLONE_FS, 0);
        let f = expand_implied(UNSHARE_EMPTY_MNTNS);
        assert_ne!(f & CLONE_NEWNS, 0);
        assert_ne!(f & CLONE_FS, 0);
    }

    #[test]
    fn vm_implies_sighand_implies_thread() {
        let f = expand_implied(CLONE_VM);
        assert_ne!(f & CLONE_SIGHAND, 0);
        assert_ne!(f & CLONE_THREAD, 0);
    }

    #[test]
    fn unknown_bits_are_einval() {
        assert_eq!(check_unshare_flags(1 << 63, true, false), Err(Errno::Einval));
        // CLONE_PIDFD / CLONE_PTRACE and friends are not unshareable.
        assert_eq!(check_unshare_flags(0x0000_1000, true, false), Err(Errno::Einval));
    }

    #[test]
    fn thread_sighand_vm_are_noops_when_single_threaded() {
        assert_eq!(check_unshare_flags(CLONE_THREAD, true, false), Ok(()));
        assert_eq!(check_unshare_flags(CLONE_SIGHAND | CLONE_THREAD, true, false), Ok(()));
        assert_eq!(check_unshare_flags(
            expand_implied(CLONE_VM), true, false), Ok(()));
    }

    #[test]
    fn thread_sighand_vm_are_einval_when_multi_threaded() {
        assert_eq!(check_unshare_flags(CLONE_THREAD, false, false), Err(Errno::Einval));
        assert_eq!(check_unshare_flags(CLONE_SIGHAND, false, false), Err(Errno::Einval));
        assert_eq!(check_unshare_flags(CLONE_VM, false, false), Err(Errno::Einval));
        // ...and so is CLONE_NEWUSER, through the CLONE_THREAD implication.
        assert_eq!(check_unshare_flags(expand_implied(CLONE_NEWUSER), false, false),
            Err(Errno::Einval));
    }

    #[test]
    fn sighand_or_vm_with_a_shared_sighand_is_einval() {
        assert_eq!(check_unshare_flags(CLONE_SIGHAND | CLONE_THREAD, true, true),
            Err(Errno::Einval));
        assert_eq!(check_unshare_flags(expand_implied(CLONE_VM), true, true),
            Err(Errno::Einval));
        // A shared sighand does NOT block the plain namespace flags.
        assert_eq!(check_unshare_flags(CLONE_NEWNET, true, true), Ok(()));
    }

    #[test]
    fn plain_resource_flags_are_accepted_multi_threaded() {
        assert_eq!(check_unshare_flags(CLONE_FILES, false, true), Ok(()));
        assert_eq!(check_unshare_flags(CLONE_FS, false, true), Ok(()));
        assert_eq!(check_unshare_flags(CLONE_SYSVSEM, false, true), Ok(()));
        assert_eq!(check_unshare_flags(CLONE_NEWNET | CLONE_NEWUTS, false, true), Ok(()));
    }

    #[test]
    fn sys_admin_is_needed_for_every_namespace_except_user_alone() {
        assert!(!needs_sys_admin(CLONE_NEWUSER));
        assert!(!needs_sys_admin(expand_implied(CLONE_NEWUSER)));
        assert!(!needs_sys_admin(CLONE_FILES | CLONE_FS | CLONE_SYSVSEM));
        for flag in [CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID,
            CLONE_NEWNET, CLONE_NEWCGROUP, CLONE_NEWTIME]
        {
            assert!(needs_sys_admin(flag), "namespace flag must be capability-gated");
            assert!(needs_sys_admin(flag | CLONE_NEWUSER));
        }
    }

    #[test]
    fn sysvsem_detach_covers_both_triggers() {
        assert!(detaches_sysvsem(CLONE_SYSVSEM));
        assert!(detaches_sysvsem(CLONE_NEWIPC));
        assert!(!detaches_sysvsem(CLONE_NEWNET | CLONE_FILES));
    }

    #[test]
    fn clone_ns_all_covers_the_eight_namespace_kinds() {
        assert_eq!(CLONE_NS_ALL.count_ones(), 8);
        assert_eq!(CLONE_NS_ALL & UNSHARE_ALLOWED, CLONE_NS_ALL);
    }
}
