// time_common — helpers shared by ≥2 time syscall handlers (docs/53 §0).
// Canonical realtime, boottime, and TAI ownership lives in `timekeeper`.

use core::sync::atomic::AtomicI32;
use namespace_identity::{NamespaceKind, NamespaceRef};
use nscg::time_ns::{TimeNsClock, TimeNsError};
use syscall::errno::Errno;

pub(crate) const NS_PER_SEC: u64 = 1_000_000_000;
pub(crate) const USEC_PER_SEC: u64 = 1_000_000;
pub(crate) const NSEC_PER_USEC: u64 = 1_000;
pub(crate) const TIMEVAL_SIZE: u64 = 16;
pub(crate) const TIMEZONE_SIZE: u64 = 8;
pub(crate) const TZ_MINUTESWEST_LIMIT: i32 = 15 * 60;

// Clock ids and the per-clock callback tables have exactly one owner,
// `sched::posix_clock` (Linux `posix_clocks[]`); these are the `u64` views for
// the raw syscall register.
pub(crate) use sched::posix_clock::ClockSpec;

/// Decode the raw `clockid_t` register — `clock_policy::classify` by another
/// name, kept local so this file stays usable as a standalone `#[path]` module
/// in the differential-conformance harness.
#[inline]
pub(crate) fn classify(clk_id: u64) -> Result<ClockSpec, Errno> {
    sched::posix_clock::classify_clock(clk_id as i32).map_err(|_| Errno::Einval)
}

pub(crate) const CLOCK_REALTIME:           u64 = sched::posix_clock::CLOCK_REALTIME as u64;
pub(crate) const CLOCK_MONOTONIC:          u64 = sched::posix_clock::CLOCK_MONOTONIC as u64;
pub(crate) const CLOCK_PROCESS_CPUTIME_ID: u64 = sched::posix_clock::CLOCK_PROCESS_CPUTIME_ID as u64;
pub(crate) const CLOCK_THREAD_CPUTIME_ID:  u64 = sched::posix_clock::CLOCK_THREAD_CPUTIME_ID as u64;
pub(crate) const CLOCK_MONOTONIC_RAW:      u64 = sched::posix_clock::CLOCK_MONOTONIC_RAW as u64;
pub(crate) const CLOCK_REALTIME_COARSE:    u64 = sched::posix_clock::CLOCK_REALTIME_COARSE as u64;
pub(crate) const CLOCK_MONOTONIC_COARSE:   u64 = sched::posix_clock::CLOCK_MONOTONIC_COARSE as u64;
pub(crate) const CLOCK_BOOTTIME:           u64 = sched::posix_clock::CLOCK_BOOTTIME as u64;
pub(crate) const CLOCK_REALTIME_ALARM:     u64 = sched::posix_clock::CLOCK_REALTIME_ALARM as u64;
pub(crate) const CLOCK_BOOTTIME_ALARM:     u64 = sched::posix_clock::CLOCK_BOOTTIME_ALARM as u64;
pub(crate) const CLOCK_TAI:                u64 = sched::posix_clock::CLOCK_TAI as u64;


pub(crate) static TZ_MINUTESWEST: AtomicI32 = AtomicI32::new(0);
pub(crate) static TZ_DSTTIME:     AtomicI32 = AtomicI32::new(0);

/// Initialise CLOCK_REALTIME from the hardware RTC at boot (Linux reads the
/// persistent clock in `timekeeping_init`). Without this the wall clock is
/// 1970 until settimeofday, so PAM/shadow account checks see accounts as
/// "password changed in the future" and reject the greeter session; TLS,
/// systemd timers and file mtimes are all wrong too. Boot, once, after the
/// monotonic timer is up.
/// # C: O(1)
pub fn init_wall_clock_from_rtc() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let secs = hal_x86_64::read_rtc_unix_secs();
        if secs != 0 {
            let rtc_ns = secs.saturating_mul(1_000_000_000);
            timekeeper::seed_realtime(rtc_ns);
        }
    }
    // aarch64: no CMOS RTC; PL031/devtree RTC init is a follow-up (offset stays
    // 0 → 1970, as before — no regression).
}

/// # C: O(1)
#[inline]
pub(crate) fn monotonic_ns() -> u64 {
    timekeeper::monotonic_ns()
}

/// # C: O(1)
#[inline]
pub(crate) fn realtime_ns() -> u64 { timekeeper::realtime_ns() }

/// Pick the native clock provider for a POSIX `clk_id`.
/// # C: O(1)
#[inline]
pub(crate) fn ns_for_clock(clk_id: u64) -> u64 {
    match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_REALTIME_ALARM => realtime_ns(),
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => timekeeper::boottime_ns(),
        CLOCK_TAI => timekeeper::tai_ns(),
        _ => monotonic_ns(),
    }
}

#[inline]
fn display_namespace_clock(clk_id: u64) -> Option<TimeNsClock> {
    match clk_id {
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE =>
            Some(TimeNsClock::Monotonic),
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => Some(TimeNsClock::Boottime),
        _ => None,
    }
}

#[inline]
fn deadline_namespace_clock(clk_id: u64) -> Option<TimeNsClock> {
    match clk_id {
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_COARSE => Some(TimeNsClock::Monotonic),
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => Some(TimeNsClock::Boottime),
        _ => None,
    }
}

/// Apply one exact TIME owner's offset to clocks virtualized by Linux time namespaces.
/// # C: O(log N)
#[inline]
pub(crate) fn namespace_clock_ns(owner: &NamespaceRef, clk_id: u64, host_ns: u64)
    -> Result<u64, TimeNsError>
{
    match display_namespace_clock(clk_id) {
        Some(clock) => nscg::time_ns::apply_display_offset(owner, clock, host_ns),
        None => Ok(host_ns),
    }
}

/// Convert one absolute namespace-relative clock value into its host clock domain.
/// # C: O(log N)
#[inline]
pub(crate) fn namespace_absolute_to_host(owner: &NamespaceRef, clk_id: u64, user_ns: u64)
    -> Result<u64, TimeNsError>
{
    match deadline_namespace_clock(clk_id) {
        Some(clock) => nscg::time_ns::absolute_to_host(owner, clock, user_ns),
        None => Ok(user_ns),
    }
}

/// Convert only absolute sleep targets; relative durations stay in duration space.
/// # C: O(log N) when absolute, O(1) when relative
#[inline]
pub(crate) fn namespace_sleep_target_to_host(owner: &NamespaceRef, clk_id: u64,
    absolute: bool, user_ns: u64) -> Result<u64, TimeNsError>
{
    if !absolute { return Ok(user_ns); }
    namespace_absolute_to_host(owner, clk_id, user_ns)
}

#[cfg(target_os = "oxide-kernel")]
fn current_time_namespace() -> Option<NamespaceRef> {
    sched::live::current()?.namespace_owner(NamespaceKind::Time)
}

/// Read a clock as visible in the current task's TIME namespace, `k_clock`
/// `clock_get_timespec` dispatch. CPU clocks (both the static
/// PROCESS/THREAD_CPUTIME_ID ids and the negative `clock_getcpuclockid(2)`
/// encodings) resolve their target through the timer subsystem, which owns the
/// canonical cumulative accounting — a private registry scan would miss
/// already-reaped threads and make the process clock run backwards.
/// # C: O(N_tasks)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn current_ns_for_clock(clk_id: u64) -> Result<u64, Errno> {
    let clock = classify(clk_id)?;
    let host_ns = match clock {
        // `pc_clock_gettime` resolves the encoded fd through `get_clock_desc`,
        // which is EINVAL until a `posix_clock` character device exists.
        ClockSpec::Dynamic => return Err(Errno::Einval),
        ClockSpec::CpuEncoded { .. } => {
            let current = sched::live::current().ok_or(Errno::Einval)?;
            sched::timers::cpu_clock_sample_ns(current, clock).ok_or(Errno::Einval)?
        }
        _ => ns_for_clock(clk_id),
    };
    match current_time_namespace() {
        Some(owner) => namespace_clock_ns(&owner, clk_id, host_ns).map_err(|_| Errno::Einval),
        None => Ok(host_ns),
    }
}

/// Convert a current task's absolute clock value into the host clock domain.
/// # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn current_sleep_target_to_host(clk_id: u64, absolute: bool, user_ns: u64)
    -> Result<u64, TimeNsError>
{
    match current_time_namespace() {
        Some(owner) => namespace_sleep_target_to_host(&owner, clk_id, absolute, user_ns),
        None => Ok(user_ns),
    }
}

/// Whether this is one of the static `posix_clocks[]` slots — the surface
/// futex/`clock_nanosleep` accept. Negative CPU/CLOCKFD encodings decode fine
/// but are not static ids.
/// # C: O(1)
#[allow(dead_code)]
#[inline]
pub(crate) fn clock_id_known(clk_id: u64) -> bool {
    clk_id <= i32::MAX as u64 && classify(clk_id).is_ok()
}

/// Whether Linux provides a `k_clock::nsleep` backend for this clock id.
/// # C: O(1)
#[inline]
pub(crate) fn clock_nanosleep_supported(clk_id: u64) -> bool {
    match classify(clk_id) {
        Ok(clock) => sched::posix_clock::nsleep_supported(clock),
        Err(_) => false,
    }
}

/// Whether this clock can wake a suspended system and requires CAP_WAKE_ALARM.
/// # C: O(1)
#[inline]
pub(crate) fn clock_is_alarm(clk_id: u64) -> bool {
    matches!(classify(clk_id), Ok(clock) if sched::posix_clock::needs_wake_alarm(clock))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> NamespaceRef {
        let owner = namespace_identity::allocate(NamespaceKind::Time,
            namespace_identity::initial(NamespaceKind::User), None).unwrap();
        nscg::time_ns::clone_from(&owner,
            &namespace_identity::initial(NamespaceKind::Time)).unwrap();
        nscg::time_ns::set_offsets(&owner, &[
            nscg::time_ns::TimeNsUpdate { clock: TimeNsClock::Monotonic,
                offset: nscg::time_ns::TimeOffset::new(2, 0).unwrap(),
                host_ns: 10_000_000_000 },
            nscg::time_ns::TimeNsUpdate { clock: TimeNsClock::Boottime,
                offset: nscg::time_ns::TimeOffset::new(5, 0).unwrap(),
                host_ns: 10_000_000_000 },
        ]).unwrap();
        owner
    }

    #[test]
    fn linux_time_namespace_clock_classes_apply_exact_offsets() {
        let owner = owner();
        for clock in [CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_MONOTONIC_COARSE] {
            assert_eq!(namespace_clock_ns(&owner, clock, 10_000_000_000).unwrap(),
                12_000_000_000);
        }
        for clock in [CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM] {
            assert_eq!(namespace_clock_ns(&owner, clock, 10_000_000_000).unwrap(),
                15_000_000_000);
        }
        for clock in [CLOCK_REALTIME, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID,
            CLOCK_REALTIME_COARSE, CLOCK_REALTIME_ALARM]
        {
            assert_eq!(namespace_clock_ns(&owner, clock, 10_000_000_000).unwrap(),
                10_000_000_000);
        }
    }

    #[test]
    fn absolute_namespace_deadlines_convert_only_virtualized_clocks() {
        let owner = owner();
        assert_eq!(namespace_absolute_to_host(&owner, CLOCK_MONOTONIC,
            12_000_000_000).unwrap(), 10_000_000_000);
        assert_eq!(namespace_absolute_to_host(&owner, CLOCK_MONOTONIC_COARSE,
            12_000_000_000).unwrap(), 10_000_000_000);
        assert_eq!(namespace_absolute_to_host(&owner, CLOCK_BOOTTIME,
            15_000_000_000).unwrap(), 10_000_000_000);
        assert_eq!(namespace_absolute_to_host(&owner, CLOCK_BOOTTIME_ALARM,
            15_000_000_000).unwrap(), 10_000_000_000);
        assert_eq!(namespace_absolute_to_host(&owner, CLOCK_MONOTONIC_RAW,
            12_000_000_000).unwrap(), 12_000_000_000);
        assert_eq!(namespace_absolute_to_host(&owner, CLOCK_REALTIME,
            12_000_000_000).unwrap(), 12_000_000_000);
        assert_eq!(namespace_absolute_to_host(&owner, CLOCK_PROCESS_CPUTIME_ID,
            12_000_000_000).unwrap(), 12_000_000_000);
        assert_eq!(namespace_sleep_target_to_host(&owner, CLOCK_MONOTONIC, false,
            12_000_000_000).unwrap(), 12_000_000_000,
            "relative duration must not receive or remove namespace offset");
    }

    #[test]
    fn known_clock_set_rejects_unknown_ids() {
        for clock in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
            CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
            CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM,
            CLOCK_BOOTTIME_ALARM, CLOCK_TAI]
        {
            assert!(clock_id_known(clock));
        }
        assert!(!clock_id_known(u64::MAX), "a sign-extended negative id is not a static slot");
        assert!(!clock_id_known(10), "CLOCK_SGI_CYCLE slot is NULL in posix_clocks[]");
        assert!(!clock_id_known(12));
        for clock in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
            CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM, CLOCK_TAI]
        {
            assert!(clock_nanosleep_supported(clock));
        }
        for clock in [CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW,
            CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE]
        {
            assert!(!clock_nanosleep_supported(clock));
        }
        assert!(clock_is_alarm(CLOCK_REALTIME_ALARM));
        assert!(clock_is_alarm(CLOCK_BOOTTIME_ALARM));
        assert!(!clock_is_alarm(CLOCK_BOOTTIME));
    }
}
