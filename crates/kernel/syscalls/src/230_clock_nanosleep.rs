// sys_clock_nanosleep per docs/15§5. Extracted from proc.rs to
// keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};
use crate::time_common::{clock_nanosleep_supported,
    current_sleep_target_to_host, ns_for_clock};

const TIMER_ABSTIME: u64 = 0x1;

/// `sys_clock_nanosleep(clk_id, flags, req, rem)` — slot 230.
///
/// Linux `SYSCALL_DEFINE4(clock_nanosleep)` (`kernel/time/posix-timers.c:1383`)
/// → `common_nsleep`/`common_nsleep_timens` → `hrtimer_nanosleep`, in this
/// order: clock admission (EINVAL / EOPNOTSUPP), `get_timespec64` (EFAULT),
/// `timespec64_valid` (EINVAL), then
///   `if (flags & TIMER_ABSTIME) rmtp = NULL;`
///   `current->restart_block.fn = do_no_restart_syscall;`
/// so the ABSTIME form can never copy remaining time out and can never leave a
/// stale continuation armed. The sleep itself, the deliverable-signal triage
/// and the interrupted tail are the SAME engine `nanosleep(2)` uses
/// (`crate::s035_nanosleep::sleep_until_deadline`) — this slot only converts
/// the clock + flags into an absolute monotonic deadline.
/// # C: O(1) + sleep cost
pub fn sys_clock_nanosleep(args: &SyscallArgs) -> i64 {
    let clk_id = args.a0;
    let flags = args.a1;
    let req   = args.a2;
    // `clockid_to_kclock(which_clock)` returning NULL is the EINVAL
    // (`posix-timers.c:1388-1391`). It is NOT "is this a static `posix_clocks[]`
    // slot": a NEGATIVE id is a CPU-clock or CLOCKFD encoding and reaches
    // `clock_posix_cpu`, which HAS `.nsleep` (`posix-cpu-timers.c:1711`). This
    // slot used `clock_id_known` — futex's static-slot predicate — so every
    // `clock_getcpuclockid(2)` clock was rejected before the `.nsleep` table
    // was ever consulted, which also made `perthread_names_self`'s EINVAL
    // unreachable (B1450).
    let Ok(spec) = crate::time_common::classify(clk_id) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    if !clock_nanosleep_supported(clk_id) {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    if crate::time_common::clock_is_alarm(clk_id) {
        let Some(cur) = sched::live::current() else {
            return -(Errno::Esrch.as_i32() as i64);
        };
        if !cur.has_cap(sched::cap::WAKE_ALARM) {
            return -(Errno::Eperm.as_i32() as i64);
        }
    }
    if let Err(rv) = validate_user_buf(req, 16, 1) { return rv; }
    // SAFETY: req validated as readable 16-byte timespec storage.
    let (secs, nsec) = unsafe {
        let s = core::ptr::read_unaligned(req as *const i64);
        let n = core::ptr::read_unaligned((req + 8) as *const i64);
        (s, n)
    };
    // `ktime_set`-clamped decode: TIMER_ABSTIME with a huge-but-valid tv_sec
    // clamps to KTIME_MAX_NS instead of an unbounded absolute deadline.
    let target_ns = match ::syscall::time::timespec_to_ns(secs, nsec) {
        Ok(ns) => ns,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let is_abs = (flags & TIMER_ABSTIME) != 0;
    // `posix-timers.c:1400-1401`: TIMER_ABSTIME forces `rmtp = NULL`, which
    // makes `restart->nanosleep.type` TT_NONE — that is what stops
    // `do_nanosleep` copying any remainder out for the absolute form.
    let rem = if is_abs { 0 } else { args.a3 };
    let Some(cur) = sched::live::current() else { return 0; };
    // CPU clocks do NOT sleep on wall time, and never touch the wall/time-
    // namespace conversion below. Linux dispatches them through
    // `k_clock::nsleep` to `posix_cpu_nsleep` -> `do_cpu_nanosleep`
    // (`kernel/time/posix-cpu-timers.c:1537-1655`), which arms a timer on the
    // CPU clock itself and blocks until a RUNNING sibling advances it past the
    // expiry. Converting to an elapsed-time deadline (what this slot used to
    // do for every clock) makes a process-CPU sleep expire on wall time.
    if sched::timers::cpu_nanosleep::is_cpu_clock(spec) {
        return cpu_clock_nanosleep(cur, spec, is_abs, target_ns, rem);
    }
    let host_target = match current_sleep_target_to_host(clk_id, is_abs, target_ns) {
        Ok(ns) => ns,
        Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    let rel_ns = if is_abs {
        let host_now = ns_for_clock(clk_id);
        if host_target <= host_now { return 0; }
        host_target - host_now
    } else {
        host_target
    };
    let deadline = monotonic().saturating_add(rel_ns);
    // Linux `current->restart_block.fn = do_no_restart_syscall` at entry: a
    // fresh sleep must not inherit the previous call's continuation, and the
    // ABSTIME arm never re-arms one.
    cur.restart_block.disarm();
    crate::s035_nanosleep::sleep_until_deadline(cur, deadline, rem, is_abs)
}

#[inline]
fn monotonic() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Linux `posix_cpu_nsleep` (`kernel/time/posix-cpu-timers.c:1630-1655`).
/// # C: O(schedules until the CPU expiry or a signal)
fn cpu_clock_nanosleep(cur: &sched::Task, spec: sched::posix_clock::ClockSpec,
                       is_abs: bool, target_ns: u64, rem: u64) -> i64 {
    use sched::timers::cpu_nanosleep::{CpuSleepExit, cpu_sleep_exit, names_self};
    // "Diagnose required errors first" (`:1637-1642`): a per-thread CPU clock
    // naming pid 0 or the caller itself can never make progress, because the
    // sleeper accrues no CPU time while it sleeps.
    if names_self(cur, spec) {
        return -(Errno::Einval.as_i32() as i64);
    }
    // `do_cpu_nanosleep` returns `posix_cpu_timer_create`'s error before it
    // blocks (`:1552-1560`), and that create is EINVAL whenever `pid_for_clock`
    // names no live task (`:390-394`).
    if sched::timers::cpu_nanosleep::sleep_clock(cur, spec).is_none() {
        return -(Errno::Einval.as_i32() as i64);
    }
    cur.restart_block.disarm();
    // SAFETY: process context on the running task with the runqueue installed;
    // the CPU-timer tick on a sibling releases the park.
    let remaining = unsafe { sched::timers::cpu_nanosleep::body(cur, spec, is_abs, target_ns) };
    match cpu_sleep_exit(is_abs, remaining) {
        CpuSleepExit::Completed => 0,
        // `:1648-1649` — abs form arms nothing and copies no remainder out.
        CpuSleepExit::RestartNoHand => syscall::restart::restart_nohand(),
        CpuSleepExit::RestartBlock => {
            if rem != 0 && write_cpu_remaining(rem, remaining) != 0 {
                return -(Errno::Efault.as_i32() as i64);
            }
            // `:1616` `restart->nanosleep.expires = ns_to_ktime(expires)` — the
            // ABSOLUTE CPU expiry, so a resume owes only the remainder.
            let expiry = cur_cpu_now(cur, spec).saturating_add(remaining);
            cur.restart_block.arm(sched::task::restart::RESTART_CPU_NANOSLEEP,
                [expiry, rem, clock_key(spec), 0, 0, 0]);
            syscall::restart::restart_block()
        }
    }
}

/// # C: O(1)
fn cur_cpu_now(cur: &sched::Task, spec: sched::posix_clock::ClockSpec) -> u64 {
    sched::timers::cpu_clock_sample_ns(cur, spec).unwrap_or(0)
}

/// Pack the clock id back into the restart payload so the continuation resumes
/// on the SAME clock (`:1659`).
/// # C: O(1)
fn clock_key(spec: sched::posix_clock::ClockSpec) -> u64 {
    use sched::posix_clock::ClockSpec;
    match spec {
        ClockSpec::CpuEncoded { pid, per_thread, measure } =>
            (1u64 << 63) | ((per_thread as u64) << 62) | ((measure as u64) << 32) | pid as u64,
        ClockSpec::Cpu(c) =>
            ((c.per_thread as u64) << 62) | ((c.measure as u64) << 32) | c.target as u64,
        _ => 0,
    }
}

/// # C: O(1)
fn write_cpu_remaining(rem: u64, left: u64) -> i64 {
    if validate_user_buf_writable(rem, 16, 1).is_err() { return -1; }
    // SAFETY: rem validated writable for a 16-byte timespec.
    unsafe {
        core::ptr::write_unaligned(rem as *mut i64, (left / 1_000_000_000) as i64);
        core::ptr::write_unaligned((rem + 8) as *mut i64, (left % 1_000_000_000) as i64);
    }
    0
}

/// Linux `posix_cpu_nsleep_restart` (`posix-cpu-timers.c:1657-1665`):
///
/// ```c
/// clockid_t which_clock = restart_block->nanosleep.clockid;
/// t = ktime_to_timespec64(restart_block->nanosleep.expires);
/// return do_cpu_nanosleep(which_clock, TIMER_ABSTIME, &t);
/// ```
///
/// Re-entered as TIMER_ABSTIME against the stored expiry, so a repeatedly
/// interrupted sleep owes only its remainder rather than restarting in full.
/// # C: O(schedules until the CPU expiry or a signal)
pub fn cpu_nanosleep_restart(cur: &sched::Task, expiry: u64, rem: u64, key: u64) -> i64 {
    let Some(spec) = clock_from_key(key) else { return -(Errno::Einval.as_i32() as i64) };
    cpu_clock_nanosleep(cur, spec, true, expiry, rem)
}

/// Inverse of [`clock_key`].
/// # C: O(1)
fn clock_from_key(key: u64) -> Option<sched::posix_clock::ClockSpec> {
    use sched::posix_clock::{ClockSpec, CpuClock};
    let measure = sched::posix_clock::cpu_measure_from_raw(((key >> 32) & 0x3fff_ffff) as u32)?;
    let per_thread = key & (1u64 << 62) != 0;
    let target = (key & 0xffff_ffff) as u32;
    if key & (1u64 << 63) != 0 {
        Some(ClockSpec::CpuEncoded { pid: target, per_thread, measure })
    } else {
        Some(ClockSpec::Cpu(CpuClock { target, per_thread, measure }))
    }
}
