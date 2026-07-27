// `do_prlimit` errno mapping shared by slots 097 getrlimit / 160 setrlimit /
// 302 prlimit64, plus the hosted tests for the ladder those three converge on.
//
// Kept OUTSIDE the `target_os = "oxide-kernel"` gate (`kernel_body.rs`) on
// purpose — like `perm_common.rs`: `sched::Task` is constructible on the host,
// so `cargo test -p syscalls` exercises the real ordering rather than only a
// QEMU boot (`CLAUDE.md` "Verify left").

use sched::rlimit::PrlimitError;
use syscall::errno::Errno;

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
