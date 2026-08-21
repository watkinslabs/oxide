// The task freezer per `32a§10`.
//
// The decision "must this task freeze" is separated from the loop that drives
// it, because the decision is where the bugs are: freezing the task that
// requested the suspend deadlocks the machine against itself, and freezing a
// no-freeze kernel thread strands whatever it was servicing.
//
// The loop's retry cadence and timeout live here too, as values, so the
// twenty-second budget and the one-to-eight millisecond backoff are checkable
// without waiting twenty seconds for them.

use core::sync::atomic::{AtomicBool, Ordering};

/// How long a freeze pass may take before it gives up.
pub const FREEZE_TIMEOUT_MS: u64 = 20_000;
/// First inter-round sleep.
pub const FREEZE_SLEEP_MIN_US: u64 = 1_000;
/// Ceiling the inter-round sleep doubles up to.
pub const FREEZE_SLEEP_MAX_US: u64 = 8_000;

/// The per-task facts the freeze decision reads.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskFreezeFacts {
    /// Removed from the live task table, but still Arc-pinned by another owner.
    pub reaped: bool,
    /// A kernel thread rather than a userspace task.
    pub kernel_thread: bool,
    /// Marked never-freeze; must keep running across the transition.
    pub nofreeze: bool,
    /// The task that asked for the suspend. Freezing it deadlocks the machine.
    pub suspend_task: bool,
    /// Already parked in the freezer.
    pub frozen: bool,
    /// Being killed for memory pressure; freezing it would stall the reclaim.
    pub oom_victim: bool,
}

/// Which classes of task the freezer is currently demanding.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FreezePhase {
    /// Userspace tasks must freeze.
    pub freezing_user: bool,
    /// Kernel threads must freeze too.
    pub freezing_kernel: bool,
}

impl FreezePhase {
    /// Nothing is being frozen. # C: O(1)
    pub const fn idle() -> Self { FreezePhase { freezing_user: false, freezing_kernel: false } }
    /// The userspace pass. # C: O(1)
    pub const fn user() -> Self { FreezePhase { freezing_user: true, freezing_kernel: false } }
    /// The kernel-thread pass, which keeps demanding userspace too. # C: O(1)
    pub const fn kernel() -> Self { FreezePhase { freezing_user: true, freezing_kernel: true } }
}

/// Whether `facts` must freeze in `phase`.
///
/// The order is the contract: the exemptions are read before either demand, so
/// a no-freeze kernel thread stays exempt during the kernel-thread pass, when
/// the demand would otherwise apply to it.
/// # C: O(1)
pub fn freezing(phase: FreezePhase, facts: TaskFreezeFacts) -> bool {
    if facts.reaped || facts.nofreeze || facts.suspend_task { return false; }
    if facts.oom_victim { return false; }
    if phase.freezing_kernel { return true; }
    phase.freezing_user && !facts.kernel_thread
}

/// Whether this task still counts against the freeze pass: it must freeze and
/// has not yet. An already-frozen task is done, not outstanding.
/// # C: O(1)
pub fn counts_outstanding(phase: FreezePhase, facts: TaskFreezeFacts) -> bool {
    freezing(phase, facts) && !facts.frozen
}

/// The next inter-round sleep, doubling to the ceiling. # C: O(1)
pub fn next_sleep_us(current: u64) -> u64 { (current * 2).min(FREEZE_SLEEP_MAX_US) }

/// How a freeze pass ended.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FreezeOutcome {
    /// Every task that had to freeze did.
    Done,
    /// A wakeup arrived; the transition is abandoned, not retried.
    Aborted,
    /// The budget ran out with tasks still outstanding.
    TimedOut,
}

/// The decision at the end of one round of the freeze loop.
///
/// Checked in the reference's order: outstanding-zero and timeout first (so a
/// pass that completes exactly as the budget expires is a success), then the
/// wakeup check.
/// # C: O(1)
pub fn round_decision(outstanding: u32, elapsed_ms: u64, wakeup: bool) -> Option<FreezeOutcome> {
    if outstanding == 0 { return Some(FreezeOutcome::Done); }
    if elapsed_ms > FREEZE_TIMEOUT_MS { return Some(FreezeOutcome::TimedOut); }
    if wakeup { return Some(FreezeOutcome::Aborted); }
    None
}

/// Whether a pass ending in `outcome` must thaw what it froze. Only success
/// leaves tasks frozen — the caller thaws them when the transition ends.
/// # C: O(1)
pub fn thaws_on(outcome: FreezeOutcome) -> bool { outcome != FreezeOutcome::Done }

// -- live freezer state ----------------------------------------------------

static FREEZING_USER: AtomicBool = AtomicBool::new(false);
static FREEZING_KERNEL: AtomicBool = AtomicBool::new(false);

/// The phase the machine is in. Read by every task at its freeze checkpoint,
/// so it is two relaxed loads and no lock.
/// # C: O(1)
pub fn phase() -> FreezePhase {
    FreezePhase {
        freezing_user: FREEZING_USER.load(Ordering::Acquire),
        freezing_kernel: FREEZING_KERNEL.load(Ordering::Acquire),
    }
}

/// Enter `phase`. # C: O(1)
pub fn set_phase(p: FreezePhase) {
    // Kernel-thread demand is published first and withdrawn last, so a task
    // sampling the two flags never sees a phase demanding more than intended.
    if p.freezing_kernel { FREEZING_KERNEL.store(true, Ordering::Release); }
    FREEZING_USER.store(p.freezing_user, Ordering::Release);
    if !p.freezing_kernel { FREEZING_KERNEL.store(false, Ordering::Release); }
}

/// Whether anything at all is being frozen — the fast path every task's freeze
/// checkpoint takes when no transition is running.
/// # C: O(1)
pub fn freezer_active() -> bool {
    FREEZING_USER.load(Ordering::Acquire) || FREEZING_KERNEL.load(Ordering::Acquire)
}

#[cfg(test)]
#[path = "freezer/tests.rs"]
mod tests;
