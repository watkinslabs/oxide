// Counted resource kinds (Linux `enum rlimit_type`).

/// A per-user counted resource. One variant per counter Linux charges
/// through `ucounts`; adding one is a matter of extending this enum and
/// charging it at the owning subsystem's admission point.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Counter {
    /// Linux `UCOUNT_RLIMIT_NPROC` — live TASKS (threads included, exactly
    /// as `RLIMIT_NPROC` counts them) owned by this account.
    Nproc,
}

impl Counter {
    /// Index into the per-key counter array. # C: O(1)
    pub(crate) const fn index(self) -> usize { match self { Self::Nproc => 0 } }
}

/// Number of counters carried per key. # C: O(1)
pub(crate) const COUNTS: usize = 1;
