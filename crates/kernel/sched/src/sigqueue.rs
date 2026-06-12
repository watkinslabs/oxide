// Per-task signal-queue methods (RT sigqueue + SIGCHLD child-exit
// events), split out of task.rs per `08§7` file-length cap. These are
// `impl Task` methods; the `rt_sigqueue` / `child_sigq` fields + their
// init live in task.rs alongside the rest of the struct.

use crate::task::{SigInfo, Task, RT_QUEUE_CAP};

impl Task {
    /// Enqueue `info` on the per-task RT signal queue for `signo`
    /// (33..=64). Returns true if accepted, false if dropped due
    /// to the per-signal cap. Caller is also responsible for
    /// setting the pending bit on `sigpending`. Standard signals
    /// (1..=31) MUST NOT use this path — they collapse to the
    /// bitmap with synthesised siginfo at delivery time.
    /// # C: O(1)
    pub fn rt_push(&self, info: SigInfo) -> bool {
        let idx = match info.signo.checked_sub(33) {
            Some(i) if (i as usize) < 32 => i as usize,
            _ => return false,
        };
        let mut g = self.rt_sigqueue.lock();
        if g[idx].len() >= RT_QUEUE_CAP { return false; }
        g[idx].push_back(info);
        true
    }

    /// Pop the longest-waiting siginfo for RT `signo` (33..=64).
    /// Returns `None` if the queue is empty (i.e. the bitmap had
    /// the bit set without a queued record — synthesised by a
    /// non-`sigqueue` source like `kill(2)` — and the caller
    /// should fall back to a synthesised siginfo). The bool reports
    /// whether the queue is empty after the pop (POSIX: bit clears
    /// when queue drains).
    /// # C: O(1)
    pub fn rt_pop(&self, signo: u32) -> (Option<SigInfo>, bool) {
        let idx = match signo.checked_sub(33) {
            Some(i) if (i as usize) < 32 => i as usize,
            _ => return (None, true),
        };
        let mut g = self.rt_sigqueue.lock();
        let info = g[idx].pop_front();
        let empty = g[idx].is_empty();
        (info, empty)
    }

    /// B117: enqueue a SIGCHLD child-exit `info` (pid=child VPID,
    /// code=CLD_*, value=exit status). Caller sets the pending bit.
    /// Capped at `RT_QUEUE_CAP`; drop oldest on overflow. Pop is the
    /// inverse (`child_sigq.lock().pop_front()` at the delivery site).
    /// # C: O(1)
    pub fn child_sigq_push(&self, info: SigInfo) {
        let mut g = self.child_sigq.lock();
        if g.len() >= RT_QUEUE_CAP { g.pop_front(); }
        g.push_back(info);
    }
}
