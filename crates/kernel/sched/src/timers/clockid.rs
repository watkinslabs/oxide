// Canonical Linux POSIX clock-id decode + per-clock capability table.
// Single owner for every clock_gettime / clock_getres / clock_settime /
// clock_nanosleep / timer_create caller, mirroring
// `kernel/time/posix-timers.c` `clockid_to_kclock()` and the `posix_clocks[]`
// `k_clock` table (which callback a clock does or does not provide IS the
// errno contract).

/// `include/uapi/linux/time.h`
pub const CLOCK_REALTIME:           i32 = 0;
pub const CLOCK_MONOTONIC:          i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID:  i32 = 3;
pub const CLOCK_MONOTONIC_RAW:      i32 = 4;
pub const CLOCK_REALTIME_COARSE:    i32 = 5;
pub const CLOCK_MONOTONIC_COARSE:   i32 = 6;
pub const CLOCK_BOOTTIME:           i32 = 7;
pub const CLOCK_REALTIME_ALARM:     i32 = 8;
pub const CLOCK_BOOTTIME_ALARM:     i32 = 9;
/// 10 is `CLOCK_SGI_CYCLE`, removed from `posix_clocks[]` — Linux EINVALs it.
pub const CLOCK_TAI:                i32 = 11;

/// `include/linux/posix-timers.h` CPU-clock encoding of negative clock ids.
const CPUCLOCK_PERTHREAD_MASK: i32 = 4;
const CPUCLOCK_CLOCK_MASK:     i32 = 3;
const CPUCLOCK_PROF:           i32 = 0;
const CPUCLOCK_VIRT:           i32 = 1;
const CPUCLOCK_SCHED:          i32 = 2;
const CLOCKFD:                 i32 = 3;
const CLOCKFD_MASK:            i32 = CPUCLOCK_PERTHREAD_MASK | CPUCLOCK_CLOCK_MASK;

/// `hrtimer_resolution` with CONFIG_HIGH_RES_TIMERS: Linux always reports one
/// nanosecond regardless of the underlying clocksource
/// (`posix_get_hrtimer_res`).
pub const HRTIMER_RES_NS: u64 = 1;
/// `KTIME_LOW_RES` / `TICK_NSEC` at this kernel's tick rate (HZ = 100). Owns
/// the accounting cadence too — `runtime::ACCOUNTING_TICK_NS` aliases it, so
/// the resolution reported to userspace can never drift from the real tick.
pub const TICK_NSEC: u64 = 10_000_000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuMeasure { Prof, Virt, Sched, Invalid }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CpuClock {
    pub target: u32,
    pub per_thread: bool,
    pub measure: CpuMeasure,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ClockSpec {
    Realtime,
    Monotonic,
    MonotonicRaw,
    RealtimeCoarse,
    MonotonicCoarse,
    Boottime,
    RealtimeAlarm,
    BoottimeAlarm,
    Tai,
    /// Negative CPU-clock encoding not yet resolved against the task registry.
    CpuEncoded { pid: u32, per_thread: bool, measure: CpuMeasure },
    Cpu(CpuClock),
    /// `CLOCKFD` dynamic POSIX clock (a `/dev/ptpN` character device fd).
    Dynamic,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ClockError { Invalid, Unsupported }

fn cpu_measure(which: i32) -> CpuMeasure {
    match which {
        CPUCLOCK_PROF  => CpuMeasure::Prof,
        CPUCLOCK_VIRT  => CpuMeasure::Virt,
        CPUCLOCK_SCHED => CpuMeasure::Sched,
        _ => CpuMeasure::Invalid,
    }
}

/// Decode one raw `clockid_t`, `clockid_to_kclock()` semantics: a negative id
/// is either a `CLOCKFD` dynamic clock or a CPU clock; a positive id outside
/// `posix_clocks[]` (and the NULL slot 10) is EINVAL.
/// # C: O(1)
pub fn classify_clock(id: i32) -> Result<ClockSpec, ClockError> {
    match id {
        CLOCK_REALTIME           => Ok(ClockSpec::Realtime),
        CLOCK_MONOTONIC          => Ok(ClockSpec::Monotonic),
        CLOCK_PROCESS_CPUTIME_ID => Ok(ClockSpec::CpuEncoded {
            pid: 0, per_thread: false, measure: CpuMeasure::Sched }),
        CLOCK_THREAD_CPUTIME_ID  => Ok(ClockSpec::CpuEncoded {
            pid: 0, per_thread: true, measure: CpuMeasure::Sched }),
        CLOCK_MONOTONIC_RAW      => Ok(ClockSpec::MonotonicRaw),
        CLOCK_REALTIME_COARSE    => Ok(ClockSpec::RealtimeCoarse),
        CLOCK_MONOTONIC_COARSE   => Ok(ClockSpec::MonotonicCoarse),
        CLOCK_BOOTTIME           => Ok(ClockSpec::Boottime),
        CLOCK_REALTIME_ALARM     => Ok(ClockSpec::RealtimeAlarm),
        CLOCK_BOOTTIME_ALARM     => Ok(ClockSpec::BoottimeAlarm),
        CLOCK_TAI                => Ok(ClockSpec::Tai),
        _ if id < 0 => {
            if id & CLOCKFD_MASK == CLOCKFD { return Ok(ClockSpec::Dynamic); }
            let measure = cpu_measure(id & CPUCLOCK_CLOCK_MASK);
            let pid = !(id >> 3);
            if pid < 0 { return Err(ClockError::Invalid); }
            Ok(ClockSpec::CpuEncoded {
                pid: pid as u32,
                per_thread: id & CPUCLOCK_PERTHREAD_MASK != 0,
                measure,
            })
        }
        _ => Err(ClockError::Invalid),
    }
}

/// Clock domain a timer/sleep actually samples. The COARSE clocks are the
/// cheap tick-cached readings of their base clock and the ALARM clocks are
/// their base clock plus an RTC suspend wakeup (`alarm_bases[]`), so both
/// read the base clock while the system is running.
/// # C: O(1)
pub fn sample_domain(clock: ClockSpec) -> ClockSpec {
    match clock {
        ClockSpec::MonotonicRaw | ClockSpec::MonotonicCoarse => ClockSpec::Monotonic,
        ClockSpec::RealtimeCoarse | ClockSpec::RealtimeAlarm => ClockSpec::Realtime,
        ClockSpec::BoottimeAlarm => ClockSpec::Boottime,
        other => other,
    }
}

/// `clock_getres()` result. Linux reports `hrtimer_resolution` for every
/// hrtimer-backed clock, `KTIME_LOW_RES` for the COARSE pair, and — via
/// `posix_cpu_clock_getres` — one nanosecond for CPUCLOCK_SCHED, otherwise
/// `(NSEC_PER_SEC + HZ - 1) / HZ`.
/// # C: O(1)
pub fn getres_ns(clock: ClockSpec) -> Result<u64, ClockError> {
    Ok(match clock {
        ClockSpec::RealtimeCoarse | ClockSpec::MonotonicCoarse => TICK_NSEC,
        ClockSpec::CpuEncoded { measure, .. } =>
            if measure == CpuMeasure::Sched { HRTIMER_RES_NS } else { TICK_NSEC },
        ClockSpec::Cpu(cpu) =>
            if cpu.measure == CpuMeasure::Sched { HRTIMER_RES_NS } else { TICK_NSEC },
        // `pc_clock_getres` resolves the encoded fd through `get_clock_desc`,
        // which is EINVAL until a `posix_clock` character device is registered.
        ClockSpec::Dynamic => return Err(ClockError::Invalid),
        _ => HRTIMER_RES_NS,
    })
}

/// Whether `clock_settime` has a `k_clock::clock_set` callback. Only
/// CLOCK_REALTIME and the CPU clocks do; the CPU setter exists solely to
/// return EPERM after validating the target.
/// # C: O(1)
pub fn settable(clock: ClockSpec) -> bool {
    matches!(clock, ClockSpec::Realtime | ClockSpec::CpuEncoded { .. } | ClockSpec::Cpu(_))
}

/// Whether `clock_adjtime` has a `k_clock::clock_adj` callback. Only
/// `clock_realtime` (`posix_clock_realtime_adj` → `do_adjtimex`) and the
/// dynamic POSIX clocks (`pc_clock_adjtime`) carry one; every other kclock is
/// Linux's EOPNOTSUPP, which `do_clock_adjtime` reports separately from the
/// EINVAL of an id outside `posix_clocks[]`. CLOCK_TAI has no `.clock_adj` of
/// its own — its offset is disciplined through CLOCK_REALTIME's `ADJ_TAI`.
/// # C: O(1)
pub fn adjustable(clock: ClockSpec) -> Result<(), ClockError> {
    match clock {
        ClockSpec::Realtime => Ok(()),
        // `pc_clock_adjtime` resolves the encoded fd through `get_clock_desc`,
        // which is EINVAL until a `posix_clock` character device is registered.
        ClockSpec::Dynamic => Err(ClockError::Invalid),
        _ => Err(ClockError::Unsupported),
    }
}

/// Whether `timer_create` has a `k_clock::timer_create` callback. The read-only
/// clocks (MONOTONIC_RAW, both COARSE) and dynamic POSIX clocks do not, which
/// is Linux's EOPNOTSUPP.
/// # C: O(1)
pub fn timer_creatable(clock: ClockSpec) -> Result<(), ClockError> {
    match clock {
        ClockSpec::MonotonicRaw | ClockSpec::RealtimeCoarse
        | ClockSpec::MonotonicCoarse | ClockSpec::Dynamic => Err(ClockError::Unsupported),
        _ => Ok(()),
    }
}

/// Whether arming this clock needs CAP_WAKE_ALARM (`alarm_timer_create`).
/// # C: O(1)
pub fn needs_wake_alarm(clock: ClockSpec) -> bool {
    matches!(clock, ClockSpec::RealtimeAlarm | ClockSpec::BoottimeAlarm)
}

/// Whether `clock_nanosleep` has a `k_clock::nsleep` callback.
/// # C: O(1)
pub fn nsleep_supported(clock: ClockSpec) -> bool {
    match clock {
        ClockSpec::MonotonicRaw | ClockSpec::RealtimeCoarse
        | ClockSpec::MonotonicCoarse | ClockSpec::Dynamic => false,
        // `clock_thread` has no `.nsleep`; `clock_process` does.
        ClockSpec::CpuEncoded { per_thread, .. } => !per_thread,
        ClockSpec::Cpu(cpu) => !cpu.per_thread,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(pid: u32, per_thread: bool, measure: i32) -> i32 {
        ((!pid as i32) << 3) | if per_thread { CPUCLOCK_PERTHREAD_MASK } else { 0 } | measure
    }

    #[test]
    fn every_posix_clocks_slot_decodes_and_slot_ten_is_einval() {
        assert_eq!(classify_clock(CLOCK_REALTIME), Ok(ClockSpec::Realtime));
        assert_eq!(classify_clock(CLOCK_MONOTONIC), Ok(ClockSpec::Monotonic));
        assert_eq!(classify_clock(CLOCK_MONOTONIC_RAW), Ok(ClockSpec::MonotonicRaw));
        assert_eq!(classify_clock(CLOCK_REALTIME_COARSE), Ok(ClockSpec::RealtimeCoarse));
        assert_eq!(classify_clock(CLOCK_MONOTONIC_COARSE), Ok(ClockSpec::MonotonicCoarse));
        assert_eq!(classify_clock(CLOCK_BOOTTIME), Ok(ClockSpec::Boottime));
        assert_eq!(classify_clock(CLOCK_REALTIME_ALARM), Ok(ClockSpec::RealtimeAlarm));
        assert_eq!(classify_clock(CLOCK_BOOTTIME_ALARM), Ok(ClockSpec::BoottimeAlarm));
        assert_eq!(classify_clock(CLOCK_TAI), Ok(ClockSpec::Tai));
        assert_eq!(classify_clock(CLOCK_PROCESS_CPUTIME_ID), Ok(ClockSpec::CpuEncoded {
            pid: 0, per_thread: false, measure: CpuMeasure::Sched }));
        assert_eq!(classify_clock(CLOCK_THREAD_CPUTIME_ID), Ok(ClockSpec::CpuEncoded {
            pid: 0, per_thread: true, measure: CpuMeasure::Sched }));
        assert_eq!(classify_clock(10), Err(ClockError::Invalid), "CLOCK_SGI_CYCLE slot is NULL");
        assert_eq!(classify_clock(12), Err(ClockError::Invalid));
        assert_eq!(classify_clock(i32::MAX), Err(ClockError::Invalid));
    }

    #[test]
    fn negative_ids_split_between_clockfd_and_cpu_encodings() {
        // clockid_to_fd(id) == ~(id >> 3); CLOCKFD ids end in CLOCKFD_MASK == 3.
        assert_eq!(classify_clock((!3i32 << 3) | CLOCKFD), Ok(ClockSpec::Dynamic));
        assert_eq!(classify_clock(encoded(42, true, CPUCLOCK_VIRT)), Ok(ClockSpec::CpuEncoded {
            pid: 42, per_thread: true, measure: CpuMeasure::Virt }));
        assert_eq!(classify_clock(encoded(7, false, CPUCLOCK_PROF)), Ok(ClockSpec::CpuEncoded {
            pid: 7, per_thread: false, measure: CpuMeasure::Prof }));
        assert_eq!(classify_clock(encoded(1, false, CPUCLOCK_SCHED)), Ok(ClockSpec::CpuEncoded {
            pid: 1, per_thread: false, measure: CpuMeasure::Sched }));
        assert_eq!(classify_clock(-1), Ok(ClockSpec::CpuEncoded {
            pid: 0, per_thread: true, measure: CpuMeasure::Invalid }),
            "CPUCLOCK_WHICH >= CPUCLOCK_MAX is rejected by pid_for_clock, not the decode");
    }

    #[test]
    fn resolutions_match_the_k_clock_getres_callbacks() {
        for id in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME,
            CLOCK_TAI, CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM]
        {
            assert_eq!(getres_ns(classify_clock(id).unwrap()), Ok(HRTIMER_RES_NS));
        }
        for id in [CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE] {
            assert_eq!(getres_ns(classify_clock(id).unwrap()), Ok(TICK_NSEC));
        }
        for id in [CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID] {
            assert_eq!(getres_ns(classify_clock(id).unwrap()), Ok(HRTIMER_RES_NS),
                "PROCESS/THREAD_CPUTIME_ID are CPUCLOCK_SCHED -> 1ns");
        }
        assert_eq!(getres_ns(classify_clock(encoded(9, false, CPUCLOCK_PROF)).unwrap()),
            Ok(TICK_NSEC), "non-SCHED CPU clocks report (NSEC_PER_SEC + HZ - 1) / HZ");
        assert_eq!(getres_ns(ClockSpec::Dynamic), Err(ClockError::Invalid));
    }

    #[test]
    fn callback_presence_tables_match_posix_clocks() {
        assert!(settable(ClockSpec::Realtime));
        for clock in [ClockSpec::Monotonic, ClockSpec::MonotonicRaw, ClockSpec::Boottime,
            ClockSpec::Tai, ClockSpec::RealtimeCoarse, ClockSpec::MonotonicCoarse,
            ClockSpec::RealtimeAlarm, ClockSpec::BoottimeAlarm, ClockSpec::Dynamic]
        {
            assert!(!settable(clock), "only clock_realtime and the CPU clocks set");
        }
        assert!(settable(classify_clock(CLOCK_PROCESS_CPUTIME_ID).unwrap()));
        for clock in [ClockSpec::MonotonicRaw, ClockSpec::RealtimeCoarse,
            ClockSpec::MonotonicCoarse, ClockSpec::Dynamic]
        {
            assert_eq!(timer_creatable(clock), Err(ClockError::Unsupported));
            assert!(!nsleep_supported(clock));
        }
        for clock in [ClockSpec::Realtime, ClockSpec::Monotonic, ClockSpec::Boottime,
            ClockSpec::Tai, ClockSpec::RealtimeAlarm, ClockSpec::BoottimeAlarm]
        {
            assert_eq!(timer_creatable(clock), Ok(()));
            assert!(nsleep_supported(clock));
        }
        assert_eq!(adjustable(ClockSpec::Realtime), Ok(()),
            "only clock_realtime has .clock_adj");
        for clock in [ClockSpec::Monotonic, ClockSpec::MonotonicRaw, ClockSpec::Boottime,
            ClockSpec::Tai, ClockSpec::RealtimeCoarse, ClockSpec::MonotonicCoarse,
            ClockSpec::RealtimeAlarm, ClockSpec::BoottimeAlarm]
        {
            assert_eq!(adjustable(clock), Err(ClockError::Unsupported),
                "a kclock without .clock_adj is EOPNOTSUPP, not EINVAL");
        }
        for id in [CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID] {
            assert_eq!(adjustable(classify_clock(id).unwrap()), Err(ClockError::Unsupported));
        }
        assert_eq!(adjustable(ClockSpec::Dynamic), Err(ClockError::Invalid));
        assert!(needs_wake_alarm(ClockSpec::RealtimeAlarm));
        assert!(needs_wake_alarm(ClockSpec::BoottimeAlarm));
        assert!(!needs_wake_alarm(ClockSpec::Boottime));
        assert!(nsleep_supported(classify_clock(CLOCK_PROCESS_CPUTIME_ID).unwrap()));
        assert!(!nsleep_supported(classify_clock(CLOCK_THREAD_CPUTIME_ID).unwrap()),
            "clock_thread has no .nsleep callback");
    }

    #[test]
    fn coarse_and_alarm_clocks_sample_their_base_clock() {
        assert_eq!(sample_domain(ClockSpec::MonotonicCoarse), ClockSpec::Monotonic);
        assert_eq!(sample_domain(ClockSpec::MonotonicRaw), ClockSpec::Monotonic);
        assert_eq!(sample_domain(ClockSpec::RealtimeCoarse), ClockSpec::Realtime);
        assert_eq!(sample_domain(ClockSpec::RealtimeAlarm), ClockSpec::Realtime);
        assert_eq!(sample_domain(ClockSpec::BoottimeAlarm), ClockSpec::Boottime);
        assert_eq!(sample_domain(ClockSpec::Tai), ClockSpec::Tai);
    }
}
