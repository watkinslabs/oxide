// CPU-time rlimits: `RLIMIT_CPU` (thread-group CPU seconds) and
// `RLIMIT_RTTIME` (one real-time thread's uninterrupted run time), the two
// limits Linux enforces from the periodic CPU-timer check rather than at a
// syscall boundary.
//
// Both share ONE ladder (`check_rlimit`): the hard limit kills, the soft limit
// nags once per second by raising `rlim_cur` after each hit. Encoding that
// once here is what keeps the two call sites from drifting apart — they differ
// only in the unit their samples are expressed in.

use super::INFINITY;

/// Nanoseconds per second. `RLIMIT_CPU` is denominated in seconds; the CPU
/// sample it is compared against is nanoseconds.
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// Microseconds per second. `RLIMIT_RTTIME` is denominated in microseconds and
/// its soft limit steps by one second per hit.
pub const US_PER_SEC: u64 = 1_000_000;

/// What the periodic check decided for one task.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpuLimitAction {
    /// Under both limits.
    None,
    /// Soft limit reached: post `SIGXCPU` to the thread group and store
    /// `next_soft` back into `rlim_cur`, so the next report is one second
    /// later rather than one per tick.
    Xcpu { next_soft: u64 },
    /// Hard limit reached: post `SIGKILL`. No soft-limit action follows.
    Kill,
}

/// Linux's shared ladder, run only when the SOFT limit is finite — an infinite
/// soft limit skips the block entirely, so a task with `soft = RLIM_INFINITY`
/// and a finite hard limit is never killed. `time`, `soft` and `hard` are all
/// in the same unit; `step` is what a soft-limit hit adds to `rlim_cur`.
///
/// Order is load-bearing: the hard test runs FIRST and returns, so a sample
/// past both limits produces a kill and no `SIGXCPU`. Each test is
/// greater-or-EQUAL (`if (time < limit) return false`), so a sample landing
/// exactly on the limit fires.
/// # C: O(1)
pub fn check_limit(time: u64, soft: u64, hard: u64, step: u64) -> CpuLimitAction {
    if soft == INFINITY { return CpuLimitAction::None; }
    if hard != INFINITY && time >= hard { return CpuLimitAction::Kill; }
    if time >= soft { return CpuLimitAction::Xcpu { next_soft: soft.saturating_add(step) }; }
    CpuLimitAction::None
}

/// `RLIMIT_CPU`: `prof_ns` is the thread group's total CPU time (user +
/// system, Linux's `CPUCLOCK_PROF` sample) and the limit pair is in SECONDS.
/// The returned `next_soft` is in seconds, ready to store back as `rlim_cur`.
/// # C: O(1)
pub fn check_cpu(prof_ns: u64, soft_secs: u64, hard_secs: u64) -> CpuLimitAction {
    if soft_secs == INFINITY { return CpuLimitAction::None; }
    let softns = soft_secs.saturating_mul(NS_PER_SEC);
    let hardns = if hard_secs == INFINITY { INFINITY } else { hard_secs.saturating_mul(NS_PER_SEC) };
    match check_limit(prof_ns, softns, hardns, NS_PER_SEC) {
        // Linux stores `soft + 1` SECONDS back, not the nanosecond value it
        // compared against: `sig->rlim[RLIMIT_CPU].rlim_cur = soft + 1`.
        CpuLimitAction::Xcpu { .. } => CpuLimitAction::Xcpu { next_soft: soft_secs.saturating_add(1) },
        other => other,
    }
}

/// `RLIMIT_RTTIME`: `rttime_us` is how long this real-time thread has run
/// without blocking, in microseconds; the limit pair is microseconds too, and
/// the soft limit steps by one second.
/// # C: O(1)
pub fn check_rttime(rttime_us: u64, soft_us: u64, hard_us: u64) -> CpuLimitAction {
    check_limit(rttime_us, soft_us, hard_us, US_PER_SEC)
}

/// Linux `watchdog`'s tick accounting, in microseconds: a real-time thread
/// accrues one TICK per periodic tick it is still the running task, and the
/// comparison unit is microseconds.
/// # C: O(1)
pub const fn ticks_to_us(ticks: u64, hz: u64) -> u64 {
    if hz == 0 { return 0; }
    ticks.saturating_mul(US_PER_SEC / hz)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_infinite_soft_limit_disables_the_hard_limit_too() {
        // Linux guards the whole block on `soft != RLIM_INFINITY`, so a task
        // with an infinite soft limit is never killed by a finite hard one.
        assert_eq!(check_limit(u64::MAX - 1, INFINITY, 10, 1), CpuLimitAction::None);
        assert_eq!(check_cpu(u64::MAX - 1, INFINITY, 10), CpuLimitAction::None);
    }

    #[test]
    fn the_hard_limit_wins_over_the_soft_one() {
        assert_eq!(check_limit(100, 10, 100, 1), CpuLimitAction::Kill);
        assert_eq!(check_limit(101, 10, 100, 1), CpuLimitAction::Kill);
    }

    #[test]
    fn both_tests_fire_on_equality() {
        assert_eq!(check_limit(10, 10, INFINITY, 1), CpuLimitAction::Xcpu { next_soft: 11 });
        assert_eq!(check_limit(9, 10, INFINITY, 1), CpuLimitAction::None);
        assert_eq!(check_limit(10, 1, 10, 1), CpuLimitAction::Kill);
    }

    #[test]
    fn cpu_limit_is_seconds_against_a_nanosecond_sample() {
        // 2 s of CPU under a 3 s soft limit is quiet; at 3 s it nags.
        assert_eq!(check_cpu(2 * NS_PER_SEC, 3, 10), CpuLimitAction::None);
        assert_eq!(check_cpu(3 * NS_PER_SEC, 3, 10), CpuLimitAction::Xcpu { next_soft: 4 });
        assert_eq!(check_cpu(10 * NS_PER_SEC, 3, 10), CpuLimitAction::Kill);
    }

    #[test]
    fn cpu_soft_bump_is_one_second_so_sigxcpu_repeats_at_1hz() {
        let mut soft = 5u64;
        // Every whole second past the soft limit produces exactly one SIGXCPU.
        for sec in 5..9u64 {
            let a = check_cpu(sec * NS_PER_SEC, soft, INFINITY);
            assert_eq!(a, CpuLimitAction::Xcpu { next_soft: sec + 1 });
            // …and the intervening sub-second samples produce none.
            let CpuLimitAction::Xcpu { next_soft } = a else { unreachable!() };
            soft = next_soft;
            assert_eq!(check_cpu(sec * NS_PER_SEC + NS_PER_SEC / 2, soft, INFINITY),
                       CpuLimitAction::None);
        }
    }

    #[test]
    fn rttime_soft_bump_is_one_second_in_microseconds() {
        assert_eq!(check_rttime(US_PER_SEC, US_PER_SEC, INFINITY),
                   CpuLimitAction::Xcpu { next_soft: 2 * US_PER_SEC });
        assert_eq!(check_rttime(5, 10, 20), CpuLimitAction::None);
        assert_eq!(check_rttime(20, 10, 20), CpuLimitAction::Kill);
    }

    #[test]
    fn tick_accounting_matches_the_usec_unit() {
        assert_eq!(ticks_to_us(0, 1000), 0);
        assert_eq!(ticks_to_us(1, 1000), 1_000);
        assert_eq!(ticks_to_us(250, 250), US_PER_SEC);
        assert_eq!(ticks_to_us(1, 0), 0);
    }

    #[test]
    fn a_zero_cpu_limit_fires_on_the_first_sample() {
        assert_eq!(check_cpu(0, 0, INFINITY), CpuLimitAction::Xcpu { next_soft: 1 });
        assert_eq!(check_cpu(0, 0, 0), CpuLimitAction::Kill);
    }
}
