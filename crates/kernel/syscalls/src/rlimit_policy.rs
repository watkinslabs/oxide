// `do_prlimit` errno mapping shared by slots 097 getrlimit / 160 setrlimit /
// 302 prlimit64, plus the hosted tests for the ladder those three converge on.
//
// Kept OUTSIDE the `target_os = "oxide-kernel"` gate (`kernel_body.rs`) on
// purpose — like `perm_common.rs`: `sched::Task` is constructible on the host,
// so `cargo test -p syscalls` exercises the real ordering rather than only a
// QEMU boot (`CLAUDE.md` "Verify left").

use sched::rlimit::PrlimitError;
use syscall::errno::Errno;

/// The `cap_sys_resource` argument slots 160 and 302 hand `do_prlimit` —
/// Linux's `capable(CAP_SYS_RESOURCE)`, which is `ns_capable(&init_user_ns, …)`
/// and NOT a plain effective-set test. The upstream comment on the check is
/// explicit that it stays pinned to the initial user namespace "until cgroups
/// can contain all limits".
///
/// Named here rather than open-coded at each slot because the slots are
/// `target_os = "oxide-kernel"`-gated and cannot be tested: both previously
/// passed `has_cap`, so root inside an unprivileged user namespace could raise
/// any hard limit after one `unshare(CLONE_NEWUSER)`.
/// # C: O(1)
pub fn cap_sys_resource(cur: &sched::Task) -> bool {
    crate::perm_common::capable(cur, sched::cap::SYS_RESOURCE)
}

/// Map a `do_prlimit` rejection to its Linux errno. # C: O(1)
pub fn errno_of(e: PrlimitError) -> Errno {
    match e {
        PrlimitError::Einval => Errno::Einval,
        PrlimitError::Eperm  => Errno::Eperm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sched::rlimit::{DEFAULT_RLIMITS, INFINITY, rlim};

    // The exact boolean slots 160/302 hand `do_prlimit`. Driving the real
    // helper rather than re-deriving it here is the point: the defect this
    // covers was a call site that computed the right answer nowhere and passed
    // an effective-set test instead, so only the composition is evidence.
    use super::cap_sys_resource as cap_arg;

    fn task() -> sched::Task {
        sched::Task::new(9001, "rlimit-test", sched::SchedClass::Normal { weight: 1024 })
    }

    #[test]
    fn bad_resource_index_is_einval() {
        let t = task();
        assert_eq!(t.do_prlimit(rlim::COUNT, None, true), Err(PrlimitError::Einval));
        assert_eq!(t.do_prlimit(usize::MAX, Some((0, 0)), true), Err(PrlimitError::Einval));
    }

    #[test]
    fn cur_above_max_is_einval_before_any_permission_test() {
        let t = task();
        // No CAP_SYS_RESOURCE and a hard-limit raise as well: Linux still
        // reports EINVAL, because the cur>max test runs first.
        assert_eq!(t.do_prlimit(rlim::CORE, Some((INFINITY, 4096)), false),
            Err(PrlimitError::Einval));
    }

    #[test]
    fn nofile_above_nr_open_is_eperm() {
        let t = task();
        let over = vfs::fdtable::nr_open() as u64 + 1;
        assert_eq!(t.do_prlimit(rlim::NOFILE, Some((over, over)), true),
            Err(PrlimitError::Eperm), "CAP_SYS_RESOURCE does NOT lift fs.nr_open");
        assert_eq!(t.rlimit(rlim::NOFILE), DEFAULT_RLIMITS[rlim::NOFILE],
            "a rejected call must not have written the table");
    }

    #[test]
    fn nofile_at_nr_open_is_accepted() {
        let t = task();
        let at = vfs::fdtable::nr_open() as u64;
        assert_eq!(t.do_prlimit(rlim::NOFILE, Some((at, at)), true), Ok((1024, 4096)));
        assert_eq!(t.rlimit(rlim::NOFILE), (at, at));
    }

    #[test]
    fn raising_the_hard_limit_needs_cap_sys_resource() {
        let t = task();
        // STACK defaults to (8 MiB, RLIM_INFINITY); use CORE, whose default
        // hard limit is finite in Linux's INIT_RLIMITS only for cur.
        t.set_rlimit(rlim::CORE, (0, 4096));
        assert_eq!(t.do_prlimit(rlim::CORE, Some((0, 8192)), false), Err(PrlimitError::Eperm));
        assert_eq!(t.rlimit(rlim::CORE), (0, 4096), "denied raise must not write");
        assert_eq!(t.do_prlimit(rlim::CORE, Some((0, 8192)), true), Ok((0, 4096)));
        assert_eq!(t.rlimit(rlim::CORE), (0, 8192));
    }

    #[test]
    fn lowering_the_hard_limit_is_unprivileged_and_irreversible() {
        let t = task();
        t.set_rlimit(rlim::CORE, (4096, 4096));
        assert_eq!(t.do_prlimit(rlim::CORE, Some((512, 512)), false), Ok((4096, 4096)));
        assert_eq!(t.rlimit(rlim::CORE), (512, 512));
        // Irreversible without the capability.
        assert_eq!(t.do_prlimit(rlim::CORE, Some((512, 4096)), false), Err(PrlimitError::Eperm));
        assert_eq!(t.rlimit(rlim::CORE), (512, 512));
    }

    #[test]
    fn old_value_is_returned_only_on_success() {
        let t = task();
        t.set_rlimit(rlim::MEMLOCK, (100, 200));
        // getrlimit shape: read-only, no permission needed.
        assert_eq!(t.do_prlimit(rlim::MEMLOCK, None, false), Ok((100, 200)));
        // A rejected write yields Err, so prlimit64 never copies `old` out.
        assert!(t.do_prlimit(rlim::MEMLOCK, Some((100, 300)), false).is_err());
    }

    #[test]
    fn hard_raise_gate_is_the_init_user_namespace_test_not_the_effective_set() {
        use core::sync::atomic::Ordering;
        use namespace_identity::{allocate, initial, NamespaceKind};

        let t = task();
        t.creds.cap_effective.store(1u64 << sched::cap::SYS_RESOURCE, Ordering::Release);
        t.set_rlimit(rlim::CORE, (0, 4096));

        // Root of a NON-initial user namespace holds a full effective set
        // there, so an effective-set-only gate would let it raise the hard
        // limit. Linux asks `capable()`, which is the init-namespace test.
        let init_user = initial(NamespaceKind::User);
        let inner = allocate(NamespaceKind::User, init_user.clone(), Some(init_user.clone())).unwrap();
        assert!(t.replace_namespace(inner).is_ok());
        assert!(t.has_cap(sched::cap::SYS_RESOURCE), "effective set still holds it");
        assert!(!cap_arg(&t), "but not in the initial user namespace");
        assert_eq!(t.do_prlimit(rlim::CORE, Some((0, 8192)), cap_arg(&t)),
            Err(PrlimitError::Eperm));
        assert_eq!(t.rlimit(rlim::CORE), (0, 4096), "denied raise must not write");

        // Back in the initial user namespace the same task may raise it.
        assert!(t.replace_namespace(init_user).is_ok());
        assert!(cap_arg(&t));
        assert_eq!(t.do_prlimit(rlim::CORE, Some((0, 8192)), cap_arg(&t)), Ok((0, 4096)));
        assert_eq!(t.rlimit(rlim::CORE), (0, 8192));
    }

    #[test]
    fn lowering_a_hard_limit_stays_unprivileged_inside_a_user_namespace() {
        use core::sync::atomic::Ordering;
        use namespace_identity::{allocate, initial, NamespaceKind};
        let t = task();
        t.creds.cap_effective.store(0, Ordering::Release);
        t.set_rlimit(rlim::CORE, (4096, 4096));
        let init_user = initial(NamespaceKind::User);
        let inner = allocate(NamespaceKind::User, init_user.clone(), Some(init_user)).unwrap();
        assert!(t.replace_namespace(inner).is_ok());
        assert_eq!(t.do_prlimit(rlim::CORE, Some((0, 512)), cap_arg(&t)), Ok((4096, 4096)));
        assert_eq!(t.rlimit(rlim::CORE), (0, 512));
    }

    #[test]
    fn errno_mapping_matches_linux() {
        assert_eq!(errno_of(PrlimitError::Einval), Errno::Einval);
        assert_eq!(errno_of(PrlimitError::Eperm), Errno::Eperm);
    }

    #[test]
    fn check_new_rlimit_ladder_is_pure_and_ordered() {
        use sched::rlimit::check_new_rlimit;
        // cur>max wins over the NOFILE ceiling.
        assert_eq!(check_new_rlimit(rlim::NOFILE, (u64::MAX, 8), 64),
            Err(PrlimitError::Einval));
        assert_eq!(check_new_rlimit(rlim::NOFILE, (8, 65), 64), Err(PrlimitError::Eperm));
        assert_eq!(check_new_rlimit(rlim::NOFILE, (8, 64), 64), Ok(()));
        // The nr_open ceiling applies to NOFILE only.
        assert_eq!(check_new_rlimit(rlim::AS, (8, u64::MAX), 64), Ok(()));
    }
}
