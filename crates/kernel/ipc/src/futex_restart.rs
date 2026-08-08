// `futex_wait()`'s restart decision on interruption.
//
// Non-gated on purpose: `live::futex` is kernel-only, and the rule below is
// the whole user-visible contract of an interrupted FUTEX_WAIT, so it lives
// where a hosted `cargo test` can reach it.

/// What an interrupted `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` must return.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FutexInterrupt {
    /// `-ERESTARTSYS`, no restart block — an untimed wait has no deadline to
    /// preserve, so re-entering `futex(2)` with the original arguments is
    /// already correct.
    RestartSys,
    /// Arm a restart block and return `-ERESTART_RESTARTBLOCK`. The block
    /// carries the ABSOLUTE deadline, so a resumed wait runs out the remaining
    /// timeout instead of starting the full one again.
    RestartBlock,
}

/// The discriminator is whether the call carried a timeout AT ALL, never
/// whether that timeout was absolute or relative. `FUTEX_WAIT`'s relative
/// timespec is converted to an absolute CLOCK_MONOTONIC deadline at syscall
/// entry, so by the time the wait actually blocks the two ops are
/// indistinguishable and both arm a restart block on interruption.
/// # C: O(1)
pub const fn futex_interrupt(deadline_ns: u64) -> FutexInterrupt {
    if deadline_ns == 0 { FutexInterrupt::RestartSys } else { FutexInterrupt::RestartBlock }
}
