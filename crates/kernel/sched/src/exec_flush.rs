// Per-thread ARCH flags `execve` resets — Linux `flush_thread()` plus
// `arch_setup_new_exec()`.
//
// Which flags survive an exec is architecture-specific and NOT symmetric, so
// this is a per-arch table rather than a single "clear everything" sweep:
//
//   PR_SET_TSC          x86_64  SURVIVES. `flush_thread()` touches the TLS
//                               array, the FPU and the debug registers, and
//                               never clears the no-TSC thread flag.
//                       arm64   RESET to `PR_TSC_ENABLE`, from
//                               `arch_setup_new_exec()`.
//   PR_SET_TAGGED_ADDR  arm64   RESET — `flush_thread()` clears the
//                               tagged-address thread flag, so a fresh image
//                               starts with the tagged-address ABI off and
//                               must opt in for itself.
//
// Copying x86's "survives" rule onto arm64 would leave a freshly-exec'd
// program unable to read the counter with no way to have asked for that, and
// copying arm64's "reset" rule onto x86 would silently drop a sandbox's TSC
// trap the first time it exec'd a helper.

use crate::task::Task;

/// Reset the per-thread arch flags this target's `execve` resets, and make the
/// CPU agree before the new image runs.
///
/// Runs past the point of no return, alongside the credential commit, so a
/// failed `execve` leaves every flag as the caller had it.
/// # C: O(1)
pub fn flush_thread_flags(cur: &Task) {
    // Linux `fpu_flush_thread` -> `pkru_write_default`: protection-key rights
    // do NOT survive exec. The new image's keys mean something else entirely,
    // so inheriting the old program's open keys would hand it access it never
    // asked for. Inert where the register does not exist.
    crate::pkru::reset_on_exec(cur);
    #[cfg(target_arch = "aarch64")]
    {
        crate::prctl::tsc::apply(cur, false);
        cur.tagged_addr.store(false, core::sync::atomic::Ordering::Release);
    }
    #[cfg(not(target_arch = "aarch64"))]
    { let _ = cur; }
}

/// Whether `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` survives `execve` on this
/// target. Pure, so the asymmetry above is pinned by a test instead of living
/// only in a comment.
/// # C: O(1)
pub const fn tsc_mode_survives_exec() -> bool {
    cfg!(not(target_arch = "aarch64"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::SchedClass;

    /// The whole point of the module: the two arches disagree, and the
    /// disagreement is Linux's, not an oversight.
    #[test]
    fn tsc_mode_exec_rule_is_per_arch() {
        assert_eq!(tsc_mode_survives_exec(), cfg!(not(target_arch = "aarch64")));
    }

    /// On the arches that reset, the flush must actually clear both flags —
    /// a flush that only stores the flag without re-arming the CPU would
    /// leave the counter trapped for a task that reports it enabled.
    #[test]
    fn flush_clears_the_reset_flags() {
        let t = Task::new(1, "exec", SchedClass::Normal { weight: 1024 });
        crate::prctl::tsc::apply(&t, true);
        t.tagged_addr.store(true, core::sync::atomic::Ordering::Release);
        flush_thread_flags(&t);
        if tsc_mode_survives_exec() {
            assert!(crate::prctl::tsc::denied(&t), "x86 keeps the TSC trap across exec");
        } else {
            assert!(!crate::prctl::tsc::denied(&t), "arm64 resets the TSC trap at exec");
            assert!(!t.tagged_addr.load(core::sync::atomic::Ordering::Acquire));
        }
    }
}
