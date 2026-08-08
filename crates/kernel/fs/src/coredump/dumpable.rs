// Whether a dying process may be dumped at all, and how carefully.
//
// Linux keeps this as `mm->flags & MMF_DUMPABLE_MASK`, set by
// `prctl(PR_SET_DUMPABLE)` and forced down by any credential change that makes
// a process's memory more privileged than its caller. `do_coredump` reads it
// twice: once to decide whether to dump, and once to decide how paranoid to be
// about where the file lands.
//
// Ungated so `cargo test` reaches it — the dispatcher that consumes it is
// kernel-target-only, where a `#[cfg(test)]` block would compile away in
// silence.

/// `SUID_DUMP_DISABLE` — no dump, by any destination.
pub const SUID_DUMP_DISABLE: i32 = 0;
/// `SUID_DUMP_USER` — the ordinary state; dump owned by the process's own uid.
pub const SUID_DUMP_USER: i32 = 1;
/// `SUID_DUMP_ROOT` — the kernel downgraded this process after a privilege
/// change. Userspace may read this back but may never request it.
pub const SUID_DUMP_ROOT: i32 = 2;

/// Linux `coredump_skip`'s dumpability arm: `cprm->dumpable == 0` means no
/// core file, no helper program, nothing.
///
/// An unrecognised value is treated as "do not dump": the only way to reach
/// one is a bug, and the failure that loses a dump is far cheaper than the one
/// that writes a non-dumpable process's memory to disk.
/// # C: O(1)
pub fn dump_allowed(dumpable: i32) -> bool {
    matches!(dumpable, SUID_DUMP_USER | SUID_DUMP_ROOT)
}

/// Linux `coredump_force_suid_safe`: only `SUID_DUMP_ROOT` — a process whose
/// dumpability the KERNEL downgraded — demands a fully qualified core path.
/// # C: O(1)
pub fn suid_safe_required(dumpable: i32) -> bool { dumpable == SUID_DUMP_ROOT }

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract `prctl(PR_SET_DUMPABLE, 0)` buys: nothing is written.
    #[test]
    fn a_non_dumpable_process_is_never_dumped() {
        assert!(!dump_allowed(SUID_DUMP_DISABLE));
        assert!(!suid_safe_required(SUID_DUMP_DISABLE));
    }

    #[test]
    fn an_ordinary_process_dumps_with_no_extra_restriction() {
        assert!(dump_allowed(SUID_DUMP_USER));
        assert!(!suid_safe_required(SUID_DUMP_USER));
    }

    /// A privilege-downgraded process still dumps — but only to an absolute
    /// path, because a relative one resolves against a cwd the unprivileged
    /// caller chose.
    #[test]
    fn a_privilege_downgraded_process_dumps_only_to_an_absolute_path() {
        assert!(dump_allowed(SUID_DUMP_ROOT));
        assert!(suid_safe_required(SUID_DUMP_ROOT));
    }

    /// Fail closed on anything the enum does not name.
    #[test]
    fn an_unknown_dumpability_does_not_dump() {
        for v in [-1, 3, 4, i32::MIN, i32::MAX] {
            assert!(!dump_allowed(v), "dumpable {v}");
            assert!(!suid_safe_required(v), "dumpable {v}");
        }
    }

    /// The numbers are ABI: `PR_GET_DUMPABLE` returns them to userspace.
    #[test]
    fn values_match_the_uapi() {
        assert_eq!((SUID_DUMP_DISABLE, SUID_DUMP_USER, SUID_DUMP_ROOT), (0, 1, 2));
    }
}

/// `PIDFD_COREDUMP*` reported through `PIDFD_GET_INFO`.
pub const PIDFD_COREDUMPED:    u32 = 1 << 0;
pub const PIDFD_COREDUMP_SKIP: u32 = 1 << 1;
pub const PIDFD_COREDUMP_USER: u32 = 1 << 2;
pub const PIDFD_COREDUMP_ROOT: u32 = 1 << 3;

/// Linux `pidfs_coredump_mask`: which rights a dump for this dumpability would
/// be taken under, or that it would be skipped entirely. Carries no
/// `PIDFD_COREDUMPED` — that bit means a dump was actually reached, which only
/// the dump path itself can say.
/// # C: O(1)
pub fn coredump_rights_mask(dumpable: i32) -> u32 {
    match dumpable {
        SUID_DUMP_USER    => PIDFD_COREDUMP_USER,
        SUID_DUMP_ROOT    => PIDFD_COREDUMP_ROOT,
        SUID_DUMP_DISABLE => PIDFD_COREDUMP_SKIP,
        // Unreachable without a bug; report "skipped" rather than implying a
        // dump was taken under rights nobody can name.
        _                 => PIDFD_COREDUMP_SKIP,
    }
}

/// The mask latched when a process actually faced the dump decision:
/// the rights arm, plus `PIDFD_COREDUMPED` when a dump was reached.
/// # C: O(1)
pub fn coredump_verdict_mask(dumpable: i32) -> u32 {
    let rights = coredump_rights_mask(dumpable);
    if dump_allowed(dumpable) { rights | PIDFD_COREDUMPED } else { rights }
}

#[cfg(test)]
mod coredump_mask_tests {
    use super::*;

    #[test]
    fn the_rights_arm_never_claims_a_dump_was_taken() {
        for d in [SUID_DUMP_DISABLE, SUID_DUMP_USER, SUID_DUMP_ROOT, 7] {
            assert_eq!(coredump_rights_mask(d) & PIDFD_COREDUMPED, 0);
        }
        assert_eq!(coredump_rights_mask(SUID_DUMP_USER), PIDFD_COREDUMP_USER);
        assert_eq!(coredump_rights_mask(SUID_DUMP_ROOT), PIDFD_COREDUMP_ROOT);
        assert_eq!(coredump_rights_mask(SUID_DUMP_DISABLE), PIDFD_COREDUMP_SKIP);
        assert_eq!(coredump_rights_mask(7), PIDFD_COREDUMP_SKIP, "an unknown state must not imply a dump");
    }

    #[test]
    fn a_verdict_claims_a_dump_exactly_when_one_was_permitted() {
        assert_eq!(coredump_verdict_mask(SUID_DUMP_USER),
                   PIDFD_COREDUMP_USER | PIDFD_COREDUMPED);
        assert_eq!(coredump_verdict_mask(SUID_DUMP_ROOT),
                   PIDFD_COREDUMP_ROOT | PIDFD_COREDUMPED);
        assert_eq!(coredump_verdict_mask(SUID_DUMP_DISABLE), PIDFD_COREDUMP_SKIP,
                   "a refused dump reports SKIP and never COREDUMPED");
        assert!(coredump_verdict_mask(SUID_DUMP_DISABLE) & PIDFD_COREDUMPED == 0);
    }

    #[test]
    fn the_verdict_and_the_dump_decision_cannot_disagree() {
        for d in [SUID_DUMP_DISABLE, SUID_DUMP_USER, SUID_DUMP_ROOT, -1, 9] {
            assert_eq!(coredump_verdict_mask(d) & PIDFD_COREDUMPED != 0, dump_allowed(d));
        }
    }
}
