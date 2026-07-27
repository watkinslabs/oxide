// Decision order for clock_gettime / clock_getres / clock_settime.
// The ORDER these checks run in is part of the ABI — EINVAL vs EFAULT vs EPERM
// for the same call differs only by sequencing — so it lives here, free of
// `target_os` gating, with the effects injected through `ClockOps`. The slot
// files (`227_*`, `228_*`, `229_*`) are shims that implement `ClockOps` over
// real user memory and the real timekeeper.

use sched::posix_clock::{self, ClockSpec};
use syscall::errno::Errno;
use syscall::time::{KTIME_SEC_MAX, NSEC_PER_SEC, timespec_to_ns};

/// Decode the raw `clockid_t` register. `clockid_t` is `int`, so only the low
/// 32 bits reach `clockid_to_kclock()`; a negative value is a CPU-clock or
/// CLOCKFD encoding, never an out-of-table id.
/// # C: O(1)
#[inline]
pub fn classify(clk_id: u64) -> Result<ClockSpec, Errno> {
    posix_clock::classify_clock(clk_id as i32).map_err(|_| Errno::Einval)
}

/// `timespec64_valid_settod()` — the value check `do_sys_settimeofday64` runs
/// BEFORE `security_settime64`'s CAP_SYS_TIME test. A `tv_sec` at or past
/// `KTIME_SEC_MAX` is rejected outright rather than clamped: the wall clock it
/// would install cannot be represented as a `ktime_t`.
/// # C: O(1)
pub fn settod_ns(sec: i64, nsec: i64) -> Result<u64, Errno> {
    let ns = timespec_to_ns(sec, nsec)?;
    if sec as u64 >= KTIME_SEC_MAX { return Err(Errno::Einval); }
    Ok(ns)
}

/// Effects a clock syscall performs, injected so their sequencing is testable.
pub trait ClockOps {
    /// `get_timespec64()` — EFAULT on a bad pointer.
    fn read_timespec(&mut self, ptr: u64) -> Result<(i64, i64), Errno>;
    /// `put_timespec64()` — EFAULT on a bad pointer.
    fn write_timespec(&mut self, ptr: u64, sec: u64, nsec: u64) -> Result<(), Errno>;
    /// `k_clock::clock_get_timespec()`; Err for a CPU clock naming no live
    /// target, matching `posix_cpu_clock_get()`.
    fn sample_ns(&mut self, clk_id: u64, clock: ClockSpec) -> Result<u64, Errno>;
    /// `validate_clock_permissions()` — whether the encoded CPU target resolves.
    fn cpu_clock_valid(&mut self, clock: ClockSpec) -> bool;
    /// `security_settime64()` — CAP_SYS_TIME.
    fn may_set_time(&mut self) -> bool;
    /// `do_sys_settimeofday64()` commit plus the absolute-timer reprojection.
    fn set_realtime(&mut self, ns: u64);
}

fn is_cpu(clock: ClockSpec) -> bool {
    matches!(clock, ClockSpec::CpuEncoded { .. } | ClockSpec::Cpu(_))
}

/// `SYSCALL_DEFINE2(clock_gettime)`.
/// # C: O(1), O(N_tasks) for a CPU clock
pub fn clock_gettime(ops: &mut impl ClockOps, clk_id: u64, tp: u64) -> Result<(), Errno> {
    let clock = classify(clk_id)?;
    let ns = ops.sample_ns(clk_id, clock)?;
    ops.write_timespec(tp, ns / NSEC_PER_SEC, ns % NSEC_PER_SEC)
}

/// `SYSCALL_DEFINE2(clock_getres)`. The resolution callback runs before the
/// `tp` NULL test, so an unresolvable CPU target is EINVAL even when the caller
/// asked for no result; a NULL `tp` otherwise returns 0 without writing.
/// # C: O(1), O(N_tasks) for a CPU clock
pub fn clock_getres(ops: &mut impl ClockOps, clk_id: u64, tp: u64) -> Result<(), Errno> {
    let clock = classify(clk_id)?;
    if is_cpu(clock) && !ops.cpu_clock_valid(clock) { return Err(Errno::Einval); }
    let res = posix_clock::getres_ns(clock).map_err(|_| Errno::Einval)?;
    if tp == 0 { return Ok(()); }
    ops.write_timespec(tp, 0, res)
}

/// `SYSCALL_DEFINE2(clock_settime)`. `!kc->clock_set` EINVAL, then
/// `get_timespec64` EFAULT, then inside the setter `timespec64_valid_settod`
/// EINVAL, and only last CAP_SYS_TIME EPERM — an unprivileged caller passing a
/// malformed value gets Linux's EINVAL, not EPERM.
/// # C: O(1)
pub fn clock_settime(ops: &mut impl ClockOps, clk_id: u64, tp: u64) -> Result<(), Errno> {
    let clock = classify(clk_id)?;
    if !posix_clock::settable(clock) { return Err(Errno::Einval); }
    let (sec, nsec) = ops.read_timespec(tp)?;
    if is_cpu(clock) {
        // `posix_cpu_clock_set`: "You can never reset a CPU clock, but we check
        // for other errors in the call before failing with EPERM."
        return Err(if ops.cpu_clock_valid(clock) { Errno::Eperm } else { Errno::Einval });
    }
    let ns = settod_ns(sec, nsec)?;
    if !ops.may_set_time() { return Err(Errno::Eperm); }
    ops.set_realtime(ns);
    Ok(())
}

#[cfg(test)]
mod tests;
