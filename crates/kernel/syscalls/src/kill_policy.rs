// `kill(2)`'s pid-argument interpretation and its result-aggregation rules.
//
// UNGATED on purpose (CLAUDE.md "Verify left" / phantom-test rule): these are
// the decisions `062_kill.rs` makes, and they are exactly the part that is
// subtle — which pid value means "my process group" vs "everyone", and how a
// fan-out over many targets folds many per-target results into one return
// value. The registry walk that consumes them is kernel-only.

use syscall::errno::Errno;

/// How `kill(2)` reads its `pid` argument (Linux `kill_something_info`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PidClass {
    /// `pid > 0` — that one process.
    Process(u32),
    /// `pid == 0` — every process in the CALLER's process group.
    CallerPgrp,
    /// `pid == -1` — every process the caller may signal, except init and the
    /// caller's own thread group.
    Broadcast,
    /// `pid < -1` — every process in process group `-pid`.
    Pgrp(u32),
    /// `pid == INT_MIN`. Negating it overflows, so Linux excludes the case
    /// outright and answers ESRCH rather than addressing process group 2^31.
    NoSuchGroup,
}

/// Decode the `pid` argument. # C: O(1)
pub fn classify(pid: i32) -> PidClass {
    if pid > 0 { return PidClass::Process(pid as u32); }
    if pid == 0 { return PidClass::CallerPgrp; }
    if pid == -1 { return PidClass::Broadcast; }
    if pid == i32::MIN { return PidClass::NoSuchGroup; }
    PidClass::Pgrp((-pid) as u32)
}

/// Folds many per-target results into `kill(2)`'s single return value for a
/// PROCESS-GROUP fan (Linux `__kill_pgrp_info`).
///
/// "If it succeeds at least once the result becomes 0 and stays 0. Otherwise
/// return the LAST error, or ESRCH if the group is empty." So one permitted
/// member makes the whole call succeed even when every other member was EPERM.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PgrpFold {
    /// `None` until the first target is visited; `Some(0)` once one succeeded.
    result: Option<i64>,
}

impl PgrpFold {
    /// Empty group — answers ESRCH until a target is visited. # C: O(1)
    pub fn new() -> Self { Self { result: None } }

    /// Record one target's result (`0` or a negative errno). # C: O(1)
    pub fn visit(&mut self, rv: i64) {
        if self.result == Some(0) { return; }
        self.result = Some(rv);
    }

    /// The syscall return value. # C: O(1)
    pub fn finish(self) -> i64 {
        self.result.unwrap_or(-(Errno::Esrch.as_i32() as i64))
    }
}

impl Default for PgrpFold {
    fn default() -> Self { Self::new() }
}

/// Folds the `kill(-1)` broadcast (Linux `kill_something_info`'s `pid == -1`
/// arm), whose rule is DIFFERENT from the process-group one:
///
///   `for_each_process: if (vpid > 1 && !same_thread_group) { err = send;
///    ++count; if (err != -EPERM) retval = err; }`
///   `ret = count ? retval : -ESRCH`
///
/// So EPERM is *swallowed*: a shell's `kill -TERM -1` that may signal nothing
/// at all still returns 0 as long as some other process existed. ESRCH means
/// "there was literally nobody to try", not "nobody was permitted".
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct BroadcastFold {
    count: usize,
    retval: i64,
}

impl BroadcastFold {
    /// # C: O(1)
    pub fn new() -> Self { Self { count: 0, retval: 0 } }

    /// Record one candidate's result. # C: O(1)
    pub fn visit(&mut self, rv: i64) {
        self.count += 1;
        if rv != -(Errno::Eperm.as_i32() as i64) { self.retval = rv; }
    }

    /// The syscall return value. # C: O(1)
    pub fn finish(self) -> i64 {
        if self.count == 0 { -(Errno::Esrch.as_i32() as i64) } else { self.retval }
    }
}

/// Linux `check_kill_permission`'s first test: `valid_signal(sig)`. Run per
/// TARGET, after the target is resolved — a `kill(2)` naming a pid that does
/// not exist answers ESRCH even when the signal number is also nonsense.
/// # C: O(1)
pub fn signal_valid(sig: i32) -> bool { (0..=64).contains(&sig) }

#[cfg(test)]
mod tests;
