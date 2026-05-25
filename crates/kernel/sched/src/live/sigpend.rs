// F167: per-task signal-pending bitmap helpers. Kernel-side ABI
// matches Linux's sigset_t bit layout: signal N sets bit (N - 1)
// of the u64 `Task::sigpending`. Signum is a typed enum so callers
// outside this crate (net, fs, etc.) don't open-code raw signal
// numbers — per docs/07§5 R04 ("no magic numbers for typed ABI
// constants"). Kept narrow on purpose; ipc::signal::Signal is the
// richer set used by sigaction / kill / signalfd.

use core::sync::atomic::Ordering;

/// Subset of Linux signal numbers the kernel raises against the
/// current task directly (peer-closed write → SIGPIPE; child exit
/// → SIGCHLD; alarm timer → SIGALRM; etc.). Numeric values match
/// Linux uapi.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Signum {
    Sigchld = 17,
    Sigpipe = 13,
    Sigalrm = 14,
    Sigterm = 15,
    Sigint  = 2,
    Sighup  = 1,
}

impl Signum {
    /// Linux signo (1-based).
    /// # C: O(1)
    pub const fn as_u8(self) -> u8 { self as u8 }
    /// Bit index in the sigpending u64 (0-based).
    /// # C: O(1)
    pub const fn bit(self) -> u64 { 1u64 << (self.as_u8() - 1) }
}

/// Raise `sig` against the currently-running task. No-op if no
/// task is current (boot path, no runqueue installed). Default
/// disposition + handler dispatch happen in the per-syscall-return
/// sig path; this only sets the pending bit.
/// # C: O(1)
pub fn send_signal_self(sig: Signum) {
    if let Some(cur) = super::schedule::current() {
        cur.sigpending.fetch_or(sig.bit(), Ordering::Release);
    }
}
