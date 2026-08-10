// The live cells behind `/proc/sys/kernel/perf_event_paranoid`,
// `perf_event_mlock_kb`, `perf_event_max_sample_rate` and
// `perf_cpu_time_max_percent`.
//
// `perf_event_open`'s work-fn lives in the `fs` crate, which `procfs` cannot
// depend on (`fs` depends on `procfs`). Owning the live values here — the crate
// both the syscall path and `/proc/sys/kernel` can see — is what keeps each
// file from becoming a dead cell that disagrees with the gate the syscall
// actually applies.
//
// The per-tick sampling budget is DERIVED from the rate rather than stored as a
// second independent knob: the throttle ladder and this file must never be able
// to disagree about what the rate is.

use core::sync::atomic::{AtomicI32, Ordering};

/// Initial value of the sampling-privilege gate.
pub const PARANOID_DEFAULT: i32 = 2;
/// Initial ceiling on samples per second, per event.
pub const SAMPLE_RATE_DEFAULT: i32 = 100_000;
/// Initial share of a tick sampling may spend, as a percentage.
pub const CPU_TIME_MAX_PERCENT_DEFAULT: i32 = 25;
/// Initial per-user ring allowance — `512 + (PAGE_SIZE / 1024)` KiB.
pub const MLOCK_KB_DEFAULT: i32 = 512 + (hal::PAGE_SIZE_BYTES as i32 / 1024);

/// `HZ`, derived from the one tick-period owner so a change to the tick rate
/// cannot leave this file quoting a stale rate.
pub const HZ: u64 = 1_000_000_000 / crate::posix_clock::TICK_NSEC;

/// The `[0, 100]` window `perf_cpu_time_max_percent` is registered over.
pub const CPU_TIME_MAX_PERCENT_BOUNDS: (i64, i64) = (0, 100);

static PARANOID:            AtomicI32 = AtomicI32::new(PARANOID_DEFAULT);
static SAMPLE_RATE:         AtomicI32 = AtomicI32::new(SAMPLE_RATE_DEFAULT);
static CPU_TIME_MAX_PCT:    AtomicI32 = AtomicI32::new(CPU_TIME_MAX_PERCENT_DEFAULT);
static MLOCK_KB:            AtomicI32 = AtomicI32::new(MLOCK_KB_DEFAULT);

/// # C: O(1)
pub fn paranoid() -> i32 { PARANOID.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_paranoid(v: i32) { PARANOID.store(v, Ordering::Relaxed); }
/// # C: O(1)
pub fn sample_rate() -> i32 { SAMPLE_RATE.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn cpu_time_max_percent() -> i32 { CPU_TIME_MAX_PCT.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_cpu_time_max_percent(v: i32) { CPU_TIME_MAX_PCT.store(v, Ordering::Relaxed); }
/// The live per-user ring allowance in KiB, as every ring mapping is admitted
/// against it. # C: O(1)
pub fn mlock_kb() -> i32 { MLOCK_KB.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_mlock_kb(v: i32) { MLOCK_KB.store(v, Ordering::Relaxed); }

/// The rate file's write gate: with dynamic throttling switched off
/// (`perf_cpu_time_max_percent` at either end of its range) the write is
/// refused outright, because the rate it sets would have nothing to enforce it.
/// Pure over the percent so the refusal is testable without a `/proc` write.
/// # C: O(1)
pub fn sample_rate_writable(cpu_time_max_percent: i32) -> bool {
    cpu_time_max_percent != 100 && cpu_time_max_percent != 0
}

/// The rate write past its gate: `EINVAL` rather than a silently ignored write.
/// # C: O(1)
pub fn set_sample_rate_checked(v: i32) -> Result<(), ()> {
    if !sample_rate_writable(cpu_time_max_percent()) { return Err(()); }
    set_sample_rate(v);
    Ok(())
}

/// # C: O(1)
pub fn set_sample_rate(v: i32) { SAMPLE_RATE.store(v, Ordering::Relaxed); }

/// The per-tick interrupt budget the throttle ladder compares against: the
/// per-second rate divided over the tick rate, rounded up. Derived, never
/// stored: a second cell could disagree with the rate `/proc` reports.
/// # C: O(1)
pub fn max_samples_per_tick() -> u64 { samples_per_tick(sample_rate(), HZ) }

/// The derivation itself, pure over both inputs. Rounds up, with a floor of
/// one: a rate below the tick rate still admits one sample per tick.
/// # C: O(1)
pub fn samples_per_tick(rate: i32, hz: u64) -> u64 {
    if hz == 0 { return u64::MAX; }
    let r = rate.max(1) as u64;
    r.div_ceil(hz)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_per_tick_rounds_up_and_never_reaches_zero() {
        assert_eq!(samples_per_tick(100_000, 100), 1000);
        assert_eq!(samples_per_tick(101, 100), 2, "rounds up, never truncates");
        assert_eq!(samples_per_tick(1, 100), 1, "a rate under HZ still admits one");
        assert_eq!(samples_per_tick(0, 100), 1);
        assert_eq!(samples_per_tick(-5, 100), 1);
    }

    /// The default rate at this kernel's HZ. A silent tick-rate change that
    /// broke the derivation would move this number.
    #[test]
    fn the_default_budget_matches_the_default_rate_over_hz() {
        assert_eq!(HZ, 100);
        assert_eq!(samples_per_tick(SAMPLE_RATE_DEFAULT, HZ), 1000);
    }

    /// A rate write is refused while dynamic throttling is off — both ends of
    /// the percent range disable it.
    #[test]
    fn a_rate_write_is_refused_while_throttling_is_disabled() {
        assert!(sample_rate_writable(25));
        assert!(sample_rate_writable(1));
        assert!(sample_rate_writable(99));
        assert!(!sample_rate_writable(0));
        assert!(!sample_rate_writable(100));
    }

    #[test]
    fn the_checked_setter_follows_the_live_percent() {
        let saved_rate = sample_rate();
        let saved_pct  = cpu_time_max_percent();
        set_cpu_time_max_percent(0);
        assert_eq!(set_sample_rate_checked(4242), Err(()));
        assert_eq!(sample_rate(), saved_rate, "a refused write changes nothing");
        set_cpu_time_max_percent(25);
        assert_eq!(set_sample_rate_checked(4242), Ok(()));
        assert_eq!(sample_rate(), 4242);
        set_sample_rate(saved_rate);
        set_cpu_time_max_percent(saved_pct);
    }
}
