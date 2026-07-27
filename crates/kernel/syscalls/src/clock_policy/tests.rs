use super::*;
use sched::posix_clock::{CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC,
    CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW, CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME,
    CLOCK_REALTIME_ALARM, CLOCK_REALTIME_COARSE, CLOCK_TAI, CLOCK_THREAD_CPUTIME_ID,
    CpuMeasure, HRTIMER_RES_NS, TICK_NSEC};

const GOOD: u64 = 0x1000;
const BAD: u64 = 0xdead;
/// Distinct per-clock samples, so a handler that silently aliased one clock to
/// another would report the wrong value rather than merely the wrong precision.
const REALTIME_NS: u64 = 1_700_000_000_000_000_000;
const MONOTONIC_NS: u64 = 4_000_000_000;
const BOOTTIME_NS: u64 = 9_000_000_000;
const TAI_NS: u64 = REALTIME_NS + 37 * NSEC_PER_SEC;
const CPU_NS: u64 = 250_000_000;

#[derive(Default)]
struct Ops {
    cpu_valid: bool,
    capable: bool,
    reads: alloc::vec::Vec<u64>,
    writes: alloc::vec::Vec<(u64, u64, u64)>,
    set_to: Option<u64>,
    value: (i64, i64),
}

impl Ops {
    fn ok() -> Self { Self { cpu_valid: true, capable: true, ..Self::default() } }
    fn with(mut self, sec: i64, nsec: i64) -> Self { self.value = (sec, nsec); self }
}

impl ClockOps for Ops {
    fn read_timespec(&mut self, ptr: u64) -> Result<(i64, i64), Errno> {
        self.reads.push(ptr);
        if ptr != GOOD { return Err(Errno::Efault); }
        Ok(self.value)
    }
    fn write_timespec(&mut self, ptr: u64, sec: u64, nsec: u64) -> Result<(), Errno> {
        self.writes.push((ptr, sec, nsec));
        if ptr != GOOD { return Err(Errno::Efault); }
        Ok(())
    }
    fn sample_ns(&mut self, _clk_id: u64, clock: ClockSpec) -> Result<u64, Errno> {
        Ok(match clock {
            ClockSpec::Realtime | ClockSpec::RealtimeCoarse | ClockSpec::RealtimeAlarm =>
                REALTIME_NS,
            ClockSpec::Monotonic | ClockSpec::MonotonicCoarse | ClockSpec::MonotonicRaw =>
                MONOTONIC_NS,
            ClockSpec::Boottime | ClockSpec::BoottimeAlarm => BOOTTIME_NS,
            ClockSpec::Tai => TAI_NS,
            ClockSpec::CpuEncoded { .. } | ClockSpec::Cpu(_) =>
                if self.cpu_valid { CPU_NS } else { return Err(Errno::Einval) },
            ClockSpec::Dynamic => return Err(Errno::Einval),
        })
    }
    fn cpu_clock_valid(&mut self, _clock: ClockSpec) -> bool { self.cpu_valid }
    fn may_set_time(&mut self) -> bool { self.capable }
    fn set_realtime(&mut self, ns: u64) { self.set_to = Some(ns); }
}

fn clockfd(fd: i32) -> u64 { (((!fd) << 3) | 3) as i32 as i64 as u64 }

fn cpu_id(pid: u32, per_thread: bool, measure: i32) -> u64 {
    let id = ((!pid as i32) << 3) | if per_thread { 4 } else { 0 } | measure;
    id as i64 as u64
}

#[test]
fn gettime_rejects_every_id_outside_posix_clocks_before_touching_the_pointer() {
    for id in [10u64, 12, 99, i32::MAX as u64] {
        let mut ops = Ops::ok();
        assert_eq!(clock_gettime(&mut ops, id, BAD), Err(Errno::Einval));
        assert!(ops.writes.is_empty(), "EINVAL precedes the copy-out, so EFAULT never wins");
    }
}

#[test]
fn gettime_reports_efault_only_after_the_clock_is_accepted() {
    let mut ops = Ops::ok();
    assert_eq!(clock_gettime(&mut ops, CLOCK_MONOTONIC as u64, BAD), Err(Errno::Efault));
    assert_eq!(ops.writes.len(), 1);
}

#[test]
fn every_static_clock_reports_its_own_time_none_aliased_to_another() {
    let expect = [
        (CLOCK_REALTIME, REALTIME_NS), (CLOCK_MONOTONIC, MONOTONIC_NS),
        (CLOCK_MONOTONIC_RAW, MONOTONIC_NS), (CLOCK_REALTIME_COARSE, REALTIME_NS),
        (CLOCK_MONOTONIC_COARSE, MONOTONIC_NS), (CLOCK_BOOTTIME, BOOTTIME_NS),
        (CLOCK_REALTIME_ALARM, REALTIME_NS), (CLOCK_BOOTTIME_ALARM, BOOTTIME_NS),
        (CLOCK_TAI, TAI_NS), (CLOCK_PROCESS_CPUTIME_ID, CPU_NS),
        (CLOCK_THREAD_CPUTIME_ID, CPU_NS),
    ];
    for (id, ns) in expect {
        let mut ops = Ops::ok();
        assert_eq!(clock_gettime(&mut ops, id as u64, GOOD), Ok(()));
        assert_eq!(ops.writes, alloc::vec![(GOOD, ns / NSEC_PER_SEC, ns % NSEC_PER_SEC)],
            "clock {id} must not alias another clock's value");
    }
    // BOOTTIME, MONOTONIC and REALTIME are three separate domains, and TAI
    // leads REALTIME by the leap-second offset — the distinctions timeout maths
    // depends on.
    assert_ne!(MONOTONIC_NS, BOOTTIME_NS);
    assert_ne!(REALTIME_NS, MONOTONIC_NS);
    assert!(TAI_NS > REALTIME_NS);
}

#[test]
fn gettime_accepts_the_negative_cpu_clock_encodings_clock_getcpuclockid_returns() {
    let mut ops = Ops::ok();
    assert_eq!(clock_gettime(&mut ops, cpu_id(1234, false, 2), GOOD), Ok(()));
    assert_eq!(ops.writes, alloc::vec![(GOOD, 0, CPU_NS)]);
    // An encoding naming no live task in the caller's namespace is EINVAL,
    // exactly like `pid_for_clock()` returning NULL.
    let mut ops = Ops { cpu_valid: false, capable: true, ..Ops::default() };
    assert_eq!(clock_gettime(&mut ops, cpu_id(4242, true, 0), GOOD), Err(Errno::Einval));
}

#[test]
fn clockfd_ids_are_einval_until_a_posix_clock_device_exists() {
    let mut ops = Ops::ok();
    assert_eq!(clock_gettime(&mut ops, clockfd(3), GOOD), Err(Errno::Einval));
    assert_eq!(clock_getres(&mut ops, clockfd(3), GOOD), Err(Errno::Einval));
    assert_eq!(classify(clockfd(3)), Ok(ClockSpec::Dynamic));
}

#[test]
fn getres_returns_the_real_resolution_and_accepts_a_null_pointer() {
    for id in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME,
        CLOCK_TAI, CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM, CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID]
    {
        let mut ops = Ops::ok();
        assert_eq!(clock_getres(&mut ops, id as u64, GOOD), Ok(()));
        assert_eq!(ops.writes, alloc::vec![(GOOD, 0, HRTIMER_RES_NS)]);
    }
    for id in [CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE] {
        let mut ops = Ops::ok();
        assert_eq!(clock_getres(&mut ops, id as u64, GOOD), Ok(()));
        assert_eq!(ops.writes, alloc::vec![(GOOD, 0, TICK_NSEC)],
            "COARSE resolution is the real tick period, not a guessed 1ms");
    }
    let mut ops = Ops::ok();
    assert_eq!(clock_getres(&mut ops, cpu_id(7, false, 0), GOOD), Ok(()));
    assert_eq!(ops.writes, alloc::vec![(GOOD, 0, TICK_NSEC)],
        "CPUCLOCK_PROF resolution is (NSEC_PER_SEC + HZ - 1) / HZ");
}

#[test]
fn getres_with_a_null_pointer_writes_nothing_but_still_validates() {
    let mut ops = Ops::ok();
    assert_eq!(clock_getres(&mut ops, CLOCK_MONOTONIC as u64, 0), Ok(()));
    assert!(ops.writes.is_empty());
    assert_eq!(clock_getres(&mut ops, 10, 0), Err(Errno::Einval));
    let mut ops = Ops { cpu_valid: false, ..Ops::default() };
    assert_eq!(clock_getres(&mut ops, cpu_id(9, false, 2), 0), Err(Errno::Einval),
        "the getres callback validates the CPU target before the NULL-res shortcut");
}

#[test]
fn settime_rejects_non_settable_clocks_before_reading_the_value() {
    for id in [CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_MONOTONIC_COARSE,
        CLOCK_REALTIME_COARSE, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM,
        CLOCK_BOOTTIME_ALARM, CLOCK_TAI]
    {
        let mut ops = Ops::ok().with(1, 0);
        assert_eq!(clock_settime(&mut ops, id as u64, GOOD), Err(Errno::Einval));
        assert!(ops.reads.is_empty(), "no clock_set callback means EINVAL before EFAULT");
        assert!(ops.set_to.is_none());
    }
}

#[test]
fn settime_order_is_clock_then_fault_then_value_then_capability() {
    // EFAULT beats the value check: an unreadable pointer never yields EINVAL.
    let mut ops = Ops::ok().with(-1, 0);
    assert_eq!(clock_settime(&mut ops, CLOCK_REALTIME as u64, BAD), Err(Errno::Efault));
    // A malformed value is EINVAL even for a caller WITHOUT CAP_SYS_TIME —
    // checking the capability first would leak EPERM here.
    for bad in [(-1i64, 0i64), (0, -1), (0, NSEC_PER_SEC as i64), (KTIME_SEC_MAX as i64, 0)] {
        let mut ops = Ops { cpu_valid: true, capable: false, ..Ops::default() }
            .with(bad.0, bad.1);
        assert_eq!(clock_settime(&mut ops, CLOCK_REALTIME as u64, GOOD), Err(Errno::Einval),
            "{bad:?} is a value error, not a permission error");
        assert!(ops.set_to.is_none());
    }
    // A well-formed value without CAP_SYS_TIME is EPERM.
    let mut ops = Ops { cpu_valid: true, capable: false, ..Ops::default() }.with(1_000, 5);
    assert_eq!(clock_settime(&mut ops, CLOCK_REALTIME as u64, GOOD), Err(Errno::Eperm));
    assert!(ops.set_to.is_none());
    // With the capability it commits the exact nanosecond value.
    let mut ops = Ops::ok().with(1_000, 5);
    assert_eq!(clock_settime(&mut ops, CLOCK_REALTIME as u64, GOOD), Ok(()));
    assert_eq!(ops.set_to, Some(1_000 * NSEC_PER_SEC + 5));
}

#[test]
fn settime_on_a_cpu_clock_is_eperm_when_the_target_resolves_and_einval_otherwise() {
    for id in [CLOCK_PROCESS_CPUTIME_ID as u64, CLOCK_THREAD_CPUTIME_ID as u64,
        cpu_id(11, false, 2)]
    {
        let mut ops = Ops::ok().with(1, 0);
        assert_eq!(clock_settime(&mut ops, id, GOOD), Err(Errno::Eperm));
        assert_eq!(ops.reads.len(), 1, "the value is read before the CPU setter runs");
        let mut ops = Ops { cpu_valid: false, capable: true, ..Ops::default() }.with(1, 0);
        assert_eq!(clock_settime(&mut ops, id, GOOD), Err(Errno::Einval));
    }
}

#[test]
fn settod_matches_timespec64_valid_settod() {
    assert_eq!(settod_ns(0, 0), Ok(0));
    assert_eq!(settod_ns(1, 999_999_999), Ok(NSEC_PER_SEC + 999_999_999));
    assert_eq!(settod_ns(-1, 0), Err(Errno::Einval));
    assert_eq!(settod_ns(0, -1), Err(Errno::Einval));
    assert_eq!(settod_ns(0, NSEC_PER_SEC as i64), Err(Errno::Einval));
    assert_eq!(settod_ns(KTIME_SEC_MAX as i64, 0), Err(Errno::Einval),
        "a ktime_t-unrepresentable wall clock is rejected, never clamped");
    assert_eq!(settod_ns(i64::MAX, 0), Err(Errno::Einval));
    assert_eq!(settod_ns(KTIME_SEC_MAX as i64 - 1, 0),
        Ok((KTIME_SEC_MAX - 1) * NSEC_PER_SEC));
}

#[test]
fn cpu_clock_decode_keeps_the_measure_and_scope_the_encoding_carried() {
    assert_eq!(classify(cpu_id(31337, true, 1)), Ok(ClockSpec::CpuEncoded {
        pid: 31337, per_thread: true, measure: CpuMeasure::Virt }));
    assert_eq!(classify(cpu_id(31337, false, 0)), Ok(ClockSpec::CpuEncoded {
        pid: 31337, per_thread: false, measure: CpuMeasure::Prof }));
    assert_eq!(classify(CLOCK_PROCESS_CPUTIME_ID as u64), Ok(ClockSpec::CpuEncoded {
        pid: 0, per_thread: false, measure: CpuMeasure::Sched }));
    assert_eq!(classify(CLOCK_THREAD_CPUTIME_ID as u64), Ok(ClockSpec::CpuEncoded {
        pid: 0, per_thread: true, measure: CpuMeasure::Sched }));
}
