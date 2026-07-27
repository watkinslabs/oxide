// `futex_wait()`'s restart decision — Linux `kernel/futex/waitwake.c:741-771`.
//
// Non-gated on purpose: `live::futex` is kernel-only, and the rule below is
// the whole user-visible contract of an interrupted FUTEX_WAIT, so it lives
// where a hosted `cargo test` can reach it.

/// What an interrupted `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` must return.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FutexInterrupt {
    /// `-ERESTARTSYS`, no restart block. `__futex_wait` produced this and
    /// `futex_wait()` returned it untouched at `waitwake.c:753-754` ("No
    /// timeout, nothing to clean up") — an untimed wait has no deadline to
    /// preserve, so re-entering `futex(2)` with the original arguments is
    /// already correct.
    RestartSys,
    /// Arm `futex_wait_restart` and return `-ERESTART_RESTARTBLOCK`
    /// (`waitwake.c:759-767`; `set_restart_fn` supplies the code). The block
    /// carries the ABSOLUTE deadline, so a resumed wait runs out the remaining
    /// timeout instead of starting the full one again.
    RestartBlock,
}

/// Linux's condition, verbatim: `if (!to) return ret;` — the discriminator is
/// whether the call carried a timeout AT ALL, never whether that timeout was
/// absolute or relative. `FUTEX_WAIT`'s relative timespec is converted to an
/// absolute CLOCK_MONOTONIC deadline at syscall entry
/// (`kernel/futex/syscalls.c:184-185`), so by the time `futex_wait()` runs the
/// two ops are indistinguishable and both arm a block.
/// # C: O(1)
pub const fn futex_interrupt(deadline_ns: u64) -> FutexInterrupt {
    if deadline_ns == 0 { FutexInterrupt::RestartSys } else { FutexInterrupt::RestartBlock }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untimed_wait_takes_the_plain_erestartsys_arm() {
        assert_eq!(futex_interrupt(0), FutexInterrupt::RestartSys);
    }

    #[test]
    fn any_timeout_arms_a_restart_block_absolute_or_relative_alike() {
        // `FUTEX_WAIT`'s relative timeout and `FUTEX_WAIT_BITSET`'s absolute
        // one both reach `futex_wait()` as an absolute deadline, so there is
        // no ABS/REL branch to test — only "has a deadline".
        for dl in [1u64, 1_000, u64::MAX] {
            assert_eq!(futex_interrupt(dl), FutexInterrupt::RestartBlock, "dl={dl}");
        }
    }
}
