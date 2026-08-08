// Hosted POSIX timer state model. Kernel glue supplies native clock samples and signal state.
// Clock-id decode and the per-clock callback tables belong to `posix_clock`.

pub(crate) use crate::posix_clock::ClockSpec;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub(crate) use crate::posix_clock::{ClockError, CpuClock, CpuMeasure};

const INT_MAX: u64 = i32::MAX as u64;

pub(crate) fn project_deadline(deadline_ns: u64, domain_now_ns: u64,
    monotonic_now_ns: u64) -> u64
{
    monotonic_now_ns.saturating_add(deadline_ns.saturating_sub(domain_now_ns))
}

pub(crate) fn next_programmed_interrupt(now_ns: u64, earliest_ns: u64,
    tick_deadline_ns: u64) -> u64
{
    // `wall_timer_interrupt` may observe a due entry while process context
    // owns the timer-state lock.  It must then return without consuming that
    // entry; programming the stale deadline would make TSC-deadline fire
    // immediately, starving the interrupted lock holder in an IRQ storm.
    // Linux defers contested hrtimer work until it can run again; retry at the
    // normal accounting cadence, while preserving sub-tick future deadlines.
    if earliest_ns <= now_ns { tick_deadline_ns } else { tick_deadline_ns.min(earliest_ns) }
}

/// Linux `hrtimer_forward_now` for the accounting tick (`tick_nohz_handler`:
/// `hrtimer_forward(&ts->sched_timer, now, TICK_NSEC)`).
///
/// The tick is an ABSOLUTE periodic deadline that only moves when it expires.
/// Deriving it as `now + TICK_NSEC` on every reprogram instead — which is what
/// this did before B1455 — lets any caller that reprograms the one-shot for an
/// unrelated reason push the tick further out. Before B1861 the syscall return
/// tail reprogrammed on every call, so a task syscalling faster than the tick
/// period could postpone the tick forever: no preemption, no CPU accounting,
/// and a `CLOCK_PROCESS_CPUTIME_ID` sleep that a busy sibling could not finish.
///
/// `0` means "never armed" (boot). A deadline still in the future is returned
/// unchanged; an expired one advances by whole periods until it is ahead of
/// `now`, so a delayed tick cannot leave a backlog that fires as a storm.
/// # C: O(1)
pub(crate) fn advance_tick(tick_deadline_ns: u64, now_ns: u64, period_ns: u64) -> u64 {
    if tick_deadline_ns > now_ns { return tick_deadline_ns; }
    if period_ns == 0 { return now_ns.saturating_add(1); }
    if tick_deadline_ns == 0 { return now_ns.saturating_add(period_ns); }
    let behind = now_ns - tick_deadline_ns;
    let periods = behind / period_ns + 1;
    tick_deadline_ns.saturating_add(periods.saturating_mul(period_ns))
}

/// Relative CLOCK_REALTIME / CLOCK_TAI timers are hrtimer-armed on
/// CLOCK_MONOTONIC so a wall-clock adjustment cannot move them
/// (`common_hrtimer_arm`). The ALARM clocks keep their own base:
/// `alarm_timer_arm` adds the relative expiry to `base->get_ktime()`.
pub(crate) fn arm_domain(clock: ClockSpec, absolute: bool) -> ClockSpec {
    if !absolute && matches!(clock, ClockSpec::Realtime | ClockSpec::Tai) {
        ClockSpec::Monotonic
    } else {
        crate::posix_clock::sample_domain(clock)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Notify {
    None,
    Signal { signo: u32, value: u64, target_tid: u32 },
    /// Linux `cpu_timer_fire`'s nanosleep branch:
    /// a timer created by `do_cpu_nanosleep` carries `it.cpu.nanosleep = true`
    /// and, when it fires, WAKES the sleeping task instead of queueing a
    /// signal. `service_wake` intercepts this before `expire`, so the
    /// signal-shaped path below never sees it.
    Wake { tid: u32 },
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TimerSetting { pub interval_ns: u64, pub value_ns: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Expiration { pub signo: u32, pub value: u64, pub target_tid: u32 }

#[derive(Copy, Clone, Debug)]
pub struct PosixTimer {
    pub(crate) allocated: bool,
    pub(crate) clock: ClockSpec,
    pub(crate) domain: ClockSpec,
    pub(crate) notify: Notify,
    pub(crate) deadline_ns: u64,
    pub(crate) interval_ns: u64,
    delivery_pending: bool,
    pending_expiry_ns: u64,
    overrun_last: u64,
}

impl PosixTimer {
    /// Slots pre-created with the thread group. Linux allocates each timer from
    /// `posix_timers_cache` with no per-process cap, so the slot table grows on
    /// demand past this point (`super::slots`); this is only the no-allocation
    /// working set every process starts with.
    pub const SLOTS: usize = 8;

    pub(crate) fn allocate(clock: ClockSpec, notify: Notify) -> Self {
        Self { allocated: true, clock, domain: crate::posix_clock::sample_domain(clock),
            notify, ..Self::default() }
    }

    pub(crate) fn set(&mut self, domain: ClockSpec, deadline_ns: u64, interval_ns: u64) {
        self.domain = domain;
        self.deadline_ns = deadline_ns;
        self.interval_ns = if deadline_ns == 0 { 0 } else { interval_ns };
        self.delivery_pending = false;
        self.pending_expiry_ns = 0;
        self.overrun_last = 0;
    }

    pub(crate) fn armed_deadline(&self) -> u64 { self.deadline_ns }

    fn forward(&mut self, now_ns: u64) {
        if self.interval_ns == 0 || self.deadline_ns > now_ns { return; }
        let periods = now_ns.saturating_sub(self.deadline_ns) / self.interval_ns + 1;
        self.deadline_ns = self.deadline_ns.saturating_add(periods.saturating_mul(self.interval_ns));
        if self.deadline_ns <= now_ns { self.deadline_ns = u64::MAX; }
    }

    pub(crate) fn reconcile_delivery(&mut self, now_ns: u64, signal_pending: bool) {
        if !self.delivery_pending || signal_pending { return; }
        if self.interval_ns != 0 {
            self.overrun_last = now_ns.saturating_sub(self.pending_expiry_ns) / self.interval_ns;
            self.forward(now_ns);
        }
        self.delivery_pending = false;
        self.pending_expiry_ns = 0;
    }

    pub(crate) fn expire(&mut self, now_ns: u64, signal_pending: bool) -> Option<Expiration> {
        self.reconcile_delivery(now_ns, signal_pending);
        if self.deadline_ns == 0 || now_ns < self.deadline_ns {
            return None;
        }
        if self.delivery_pending {
            self.forward(now_ns);
            return None;
        }
        let (signo, value, target_tid) = match self.notify {
            // A nanosleep timer never produces a signal event; its wake is
            // handled in `service_wake`. Treated as SIGEV_NONE here so a
            // stray call cannot manufacture a delivery.
            Notify::Wake { .. } | Notify::None => {
                if self.interval_ns == 0 { self.deadline_ns = 0; }
                else { self.forward(now_ns); }
                return None;
            }
            Notify::Signal { signo, value, target_tid } => (signo, value, target_tid),
        };
        self.delivery_pending = true;
        self.pending_expiry_ns = self.deadline_ns;
        if self.interval_ns == 0 { self.deadline_ns = 0; }
        Some(Expiration { signo, value, target_tid })
    }

    pub(crate) fn setting(&mut self, now_ns: u64, signal_pending: bool) -> TimerSetting {
        self.reconcile_delivery(now_ns, signal_pending);
        if self.interval_ns != 0 && (self.delivery_pending || self.notify == Notify::None) {
            self.forward(now_ns);
        }
        let value_ns = if self.delivery_pending && self.interval_ns == 0 {
            1
        } else {
            self.deadline_ns.saturating_sub(now_ns)
        };
        TimerSetting { interval_ns: self.interval_ns, value_ns }
    }

    pub(crate) fn overrun_last(&mut self, now_ns: u64, signal_pending: bool) -> i64 {
        self.reconcile_delivery(now_ns, signal_pending);
        self.overrun_last.min(INT_MAX) as i64
    }
}

impl Default for PosixTimer {
    fn default() -> Self {
        Self {
            allocated: false,
            clock: ClockSpec::Monotonic,
            domain: ClockSpec::Monotonic,
            notify: Notify::None,
            deadline_ns: 0,
            interval_ns: 0,
            delivery_pending: false,
            pending_expiry_ns: 0,
            overrun_last: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_wall_timers_arm_on_monotonic_but_alarm_clocks_keep_their_base() {
        assert_eq!(arm_domain(ClockSpec::Realtime, false), ClockSpec::Monotonic);
        assert_eq!(arm_domain(ClockSpec::Realtime, true), ClockSpec::Realtime);
        assert_eq!(arm_domain(ClockSpec::Tai, false), ClockSpec::Monotonic);
        assert_eq!(arm_domain(ClockSpec::Tai, true), ClockSpec::Tai);
        assert_eq!(arm_domain(ClockSpec::RealtimeAlarm, false), ClockSpec::Realtime);
        assert_eq!(arm_domain(ClockSpec::BoottimeAlarm, false), ClockSpec::Boottime);
        assert_eq!(arm_domain(ClockSpec::Boottime, false), ClockSpec::Boottime);
        assert_eq!(PosixTimer::allocate(ClockSpec::RealtimeAlarm, Notify::None).domain,
            ClockSpec::Realtime);
    }

    #[test]
    fn native_deadlines_project_by_remaining_duration() {
        assert_eq!(project_deadline(1_050, 1_000, 400), 450);
        assert_eq!(project_deadline(900, 1_000, 400), 400);
        assert_eq!(project_deadline(u64::MAX, 0, 10), u64::MAX);
    }

    #[test]
    fn sub_tick_wall_deadline_programs_and_fires_at_irq() {
        let mut timer = PosixTimer::allocate(ClockSpec::Monotonic,
            Notify::Signal { signo: 14, value: 9, target_tid: 0 });
        timer.set(ClockSpec::Monotonic, 5_000_000, 0);
        let programmed = next_programmed_interrupt(0, timer.armed_deadline(), 10_000_000);
        assert_eq!(programmed, 5_000_000);
        assert!(timer.expire(programmed - 1, false).is_none());
        assert_eq!(timer.expire(programmed, false),
            Some(Expiration { signo: 14, value: 9, target_tid: 0 }));
    }

    #[test]
    fn overdue_deadline_retries_at_accounting_tick() {
        assert_eq!(next_programmed_interrupt(100, 100, 110), 110);
        assert_eq!(next_programmed_interrupt(100, 99, 110), 110);
        assert_eq!(next_programmed_interrupt(100, 105, 110), 105);
    }

    #[test]
    fn a_tick_still_ahead_is_never_pushed_further_out() {
        // A task syscalling faster than the period must not postpone its own
        // tick, including if an unrelated mutation reprograms the one-shot.
        let armed = advance_tick(0, 1_000, 10_000);
        assert_eq!(armed, 11_000);
        for now in [1_001, 2_000, 5_000, 10_999] {
            assert_eq!(advance_tick(armed, now, 10_000), armed);
        }
    }

    #[test]
    fn an_expired_tick_advances_by_whole_periods_past_now() {
        // Linux `hrtimer_forward`: one deadline ahead of `now`, no backlog.
        assert_eq!(advance_tick(11_000, 11_000, 10_000), 21_000);
        assert_eq!(advance_tick(11_000, 11_001, 10_000), 21_000);
        assert_eq!(advance_tick(11_000, 45_000, 10_000), 51_000);
        assert!(advance_tick(11_000, 1_000_000, 10_000) > 1_000_000);
    }

    #[test]
    fn an_unarmed_tick_arms_one_period_out() {
        assert_eq!(advance_tick(0, 0, 10_000), 10_000);
        assert_eq!(advance_tick(0, 7, 10_000), 10_007);
    }

    #[test]
    fn a_zero_period_still_produces_a_future_deadline() {
        assert_eq!(advance_tick(0, 100, 0), 101);
        assert_eq!(advance_tick(500, 100, 0), 500);
    }

    #[test]
    fn disarm_clears_interval_and_set_resets_cached_overrun() {
        let mut timer = PosixTimer::allocate(ClockSpec::Monotonic,
            Notify::Signal { signo: 14, value: 3, target_tid: 0 });
        timer.set(ClockSpec::Monotonic, 10, 4);
        assert!(timer.expire(10, false).is_some());
        timer.reconcile_delivery(23, false);
        assert_eq!(timer.overrun_last(23, false), 3);
        assert_eq!(timer.overrun_last(23, false), 3, "getoverrun is a cached read");
        timer.set(ClockSpec::Monotonic, 0, 99);
        assert_eq!(timer.setting(30, false), TimerSetting::default());
        assert_eq!(timer.overrun_last(30, false), 0);
    }

    #[test]
    fn pending_periodic_gettime_forwards_beyond_now_without_delivering() {
        let mut timer = PosixTimer::allocate(ClockSpec::Monotonic,
            Notify::Signal { signo: 14, value: 0, target_tid: 0 });
        timer.set(ClockSpec::Monotonic, 100, 10);
        assert!(timer.expire(100, false).is_some());
        assert_eq!(timer.setting(135, true), TimerSetting { interval_ns: 10, value_ns: 5 });
        assert_eq!(timer.overrun_last(135, true), 0, "pending overruns are not last-delivered");
        timer.reconcile_delivery(136, false);
        assert_eq!(timer.overrun_last(136, false), 3);
        assert_eq!(timer.setting(136, false).value_ns, 4);
    }

    #[test]
    fn pending_periodic_expiry_advances_without_queuing_another_signal() {
        let mut timer = PosixTimer::allocate(ClockSpec::Monotonic,
            Notify::Signal { signo: 14, value: 0, target_tid: 0 });
        timer.set(ClockSpec::Monotonic, 100, 10);
        assert!(timer.expire(100, false).is_some());
        assert!(timer.expire(135, true).is_none());
        assert_eq!(timer.armed_deadline(), 140);
        timer.reconcile_delivery(136, false);
        assert_eq!(timer.overrun_last(136, false), 3);
    }

    #[test]
    fn sigev_none_periodic_expiry_is_forwarded_by_gettime() {
        let mut timer = PosixTimer::allocate(ClockSpec::Boottime, Notify::None);
        timer.set(ClockSpec::Boottime, 50, 7);
        assert!(timer.expire(70, false).is_none());
        assert_eq!(timer.setting(70, false), TimerSetting { interval_ns: 7, value_ns: 1 });
        assert_eq!(timer.overrun_last(70, false), 0);
    }
}
