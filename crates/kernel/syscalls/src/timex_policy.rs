// Decision order for `adjtimex(2)` (`kernel/time/time.c`) and
// `clock_adjtime(2)` (`kernel/time/posix-timers.c`). The two differ in three
// observable ways and nothing else, so they live together:
//
//   * `clock_adjtime` copies the buffer in BEFORE looking at `which_clock`, so
//     a bad pointer is EFAULT even for a nonsense clock id;
//   * a valid clock id with no `k_clock::clock_adj` is EOPNOTSUPP, distinct
//     from the EINVAL of an id outside `posix_clocks[]`;
//   * `adjtimex` copies back UNCONDITIONALLY (`return copy_to_user(...) ?
//     -EFAULT : ret;`) while `clock_adjtime` copies back only on success.
//
// Not `target_os`-gated, per the module note in `clock_policy.rs`: this
// ordering is the whole observable surface of a failed call.

use sched::posix_clock::{self, ClockError};
use syscall::errno::Errno;
use timekeeper::ntp::Timex;

/// Effects, injected so the sequence above is testable without a kernel.
pub trait TimexOps {
    /// `copy_from_user(&ktx, utx, sizeof(ktx))`.
    fn read_timex(&mut self, ptr: u64) -> Result<Timex, Errno>;
    /// `copy_to_user(utx, &ktx, sizeof(ktx))`.
    fn write_timex(&mut self, ptr: u64, tx: &Timex) -> Result<(), Errno>;
    /// `capable(CAP_SYS_TIME)`, sampled once and handed to the validator so a
    /// read-only query never consults it for permission it does not need.
    fn may_set_time(&mut self) -> bool;
    /// `do_adjtimex()` — validation, the optional wall-clock step, the
    /// discipline loop, and the absolute-deadline reprojection. Returns the
    /// `TIME_*` clock state that is this syscall's success value.
    fn adjtimex(&mut self, tx: &mut Timex, capable: bool) -> Result<i32, Errno>;
}

/// `do_clock_adjtime()`'s clock admission: EINVAL for an id `posix_clocks[]`
/// has no entry for, EOPNOTSUPP for an entry with no `clock_adj` callback.
/// # C: O(1)
pub fn clock_supports_adj(clk_id: u64) -> Result<(), Errno> {
    let clock = posix_clock::classify_clock(clk_id as i32).map_err(|_| Errno::Einval)?;
    posix_clock::adjustable(clock).map_err(|e| match e {
        ClockError::Unsupported => Errno::Eopnotsupp,
        ClockError::Invalid => Errno::Einval,
    })
}

/// `SYSCALL_DEFINE1(adjtimex)`. The write-back is unconditional, so a caller
/// whose buffer became unwritable sees EFAULT even when the adjustment itself
/// was rejected — and a successful adjustment into an unwritable buffer is
/// EFAULT despite having already taken effect, exactly as in Linux.
/// # C: O(1)
pub fn adjtimex(ops: &mut impl TimexOps, ptr: u64) -> Result<i32, Errno> {
    let mut tx = ops.read_timex(ptr)?;
    let capable = ops.may_set_time();
    let result = ops.adjtimex(&mut tx, capable);
    ops.write_timex(ptr, &tx)?;
    result
}

/// `SYSCALL_DEFINE2(clock_adjtime)`.
/// # C: O(1)
pub fn clock_adjtime(ops: &mut impl TimexOps, clk_id: u64, ptr: u64) -> Result<i32, Errno> {
    let mut tx = ops.read_timex(ptr)?;
    clock_supports_adj(clk_id)?;
    let capable = ops.may_set_time();
    let state = ops.adjtimex(&mut tx, capable)?;
    ops.write_timex(ptr, &tx)?;
    Ok(state)
}

#[cfg(test)]
mod tests;
