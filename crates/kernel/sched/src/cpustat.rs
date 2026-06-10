//! System-wide CPU-time accounting for `/proc/stat` (htop/btop %CPU). Each
//! timer tick buckets into user/system/idle by the interrupted task's class.
//! htop computes %CPU from deltas between reads, so raw tick counts suffice —
//! the unit cancels in the ratio (no USER_HZ conversion needed).
//!
//! user-vs-system is approximated by task class (a running user task → user,
//! a kthread → system); a precise split would inspect the timer-IRQ frame's
//! privilege level (arch-specific) — deferred until it matters.

use core::sync::atomic::{AtomicU64, Ordering};

static USER: AtomicU64 = AtomicU64::new(0);
static SYS:  AtomicU64 = AtomicU64::new(0);
static IDLE: AtomicU64 = AtomicU64::new(0);

/// What the timer tick interrupted.
pub enum TickKind { User, System, Idle }

/// Charge one timer tick to the running context's bucket. Called from the
/// timer-ISR tick hook with the interrupted task's class.
/// # C: O(1)
pub fn account(kind: TickKind) {
    match kind {
        TickKind::User   => USER.fetch_add(1, Ordering::Relaxed),
        TickKind::System => SYS.fetch_add(1, Ordering::Relaxed),
        TickKind::Idle   => IDLE.fetch_add(1, Ordering::Relaxed),
    };
}

/// `(user, system, idle)` accumulated tick counts for `/proc/stat`'s `cpu` line.
/// # C: O(1)
pub fn snapshot() -> (u64, u64, u64) {
    (USER.load(Ordering::Relaxed), SYS.load(Ordering::Relaxed), IDLE.load(Ordering::Relaxed))
}
