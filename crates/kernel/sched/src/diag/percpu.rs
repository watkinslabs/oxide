// Per-CPU heartbeat + cross-CPU hard-lockup detector.
//
// The single-CPU watchdog (`super::watchdog_tick`) and the serial sysrq
// both run on the BSP timer tick — so a BSP-side hard freeze (a kernel
// spin with IRQs masked, e.g. a spinlock deadlock) silences *both*: the
// frozen CPU stops servicing its own tick. The only way to see that is
// from a *different* CPU.
//
// Each CPU stamps a heartbeat (monotonic ns + a snapshot of what it was
// running) into its per-CPU slot every timer tick. Any CPU that is still
// ticking periodically scans the others; if a CPU's heartbeat has gone
// stale past the threshold it is wedged, and we emit a one-shot report
// naming the CPU and what it was last running (task + last syscall).
//
// Coverage note: this needs a second CPU that is still taking timer ticks.
// Both arches bring their secondaries fully up and tick on them, so a frozen
// BSP is observed by a secondary and vice-versa. The on-demand sysrq per-CPU
// dump + the NMI backtrace (super::nmi) remain the single-CPU fallbacks.
//
// A CPU parked in its idle loop is EXCLUDED (see `idle_enter`): it owes no
// heartbeat, and reporting it buried real stalls under one line per idle CPU.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const MAX: usize = cpu::MAX_CPUS;

/// Monotonic ns of each CPU's last heartbeat.
static HB_NS: [AtomicU64; MAX] = [const { AtomicU64::new(0) }; MAX];
/// tid of the task each CPU was running at its last heartbeat.
static HB_TID: [AtomicU32; MAX] = [const { AtomicU32::new(0) }; MAX];
/// That task's last-entered syscall nr (x86 table key; u32::MAX = none).
static HB_SYS: [AtomicU32; MAX] = [const { AtomicU32::new(u32::MAX) }; MAX];
/// nr_running on that CPU's runqueue at the last heartbeat.
static HB_RUN: [AtomicU32; MAX] = [const { AtomicU32::new(0) }; MAX];
/// Whether this CPU has ever heartbeated (i.e. is online + ticking).
static HB_SEEN: [AtomicBool; MAX] = [const { AtomicBool::new(false) }; MAX];
/// Total timer ticks taken by each CPU. Advancing on CPU `x` is the proof
/// that `x` owns a live local timer; a frozen value is what `newly_stalled`
/// turns into a report.
static HB_TICKS: [AtomicU64; MAX] = [const { AtomicU64::new(0) }; MAX];
/// Whether each CPU is parked in the idle loop's halt/wfi. A CPU that is
/// idle by construction takes no timer interrupt it is obliged to take, so
/// it is excluded from the stall scan — Linux likewise never soft-lockup
/// warns about an idle CPU (its watchdog is touched on the idle path and
/// suspended for a NO_HZ-idle CPU).
static HB_IDLE: [AtomicBool; MAX] = [const { AtomicBool::new(false) }; MAX];
/// One-shot latch so each distinct stall is reported once.
static HB_STUCK: [AtomicBool; MAX] = [const { AtomicBool::new(false) }; MAX];

/// Last cross-CPU scan time (throttles the O(MAX) scan to ~1/s).
static LAST_SCAN_NS: AtomicU64 = AtomicU64::new(0);

/// A CPU whose heartbeat is older than this is treated as wedged.
const STALL_NS: u64 = 10_000_000_000; // 10s
/// Minimum spacing between cross-CPU scans.
const SCAN_INTERVAL_NS: u64 = 1_000_000_000; // 1s

/// Pure decision: is CPU `x` newly stalled? Returns true exactly when it
/// should fire (stale past threshold and not already latched). Host-tested.
/// # C: O(1)
pub fn newly_stalled(age_ns: u64, already_latched: bool) -> bool {
    age_ns >= STALL_NS && !already_latched
}

/// Full stall predicate: a CPU is reported only when it is stale, unlatched,
/// AND not parked in its idle loop. The idle term is the whole difference
/// between "this CPU is wedged" and "this CPU has nothing to do" — Linux
/// never soft-lockup warns about the latter, and reporting it buries a real
/// stall in noise from every legitimately idle CPU.
/// # C: O(1)
pub fn should_report_stall(age_ns: u64, already_latched: bool, parked_idle: bool) -> bool {
    !parked_idle && newly_stalled(age_ns, already_latched)
}

/// Called from every CPU's timer tick. Stamps this CPU's heartbeat and,
/// at most once per `SCAN_INTERVAL_NS`, scans the other CPUs for a stall.
/// # SAFETY: timer-ISR context; lock-free atomics only.
/// # C: O(1) heartbeat; O(MAX) on the throttled scan tick.
pub fn tick() {
    let cpu = this_cpu_id() as usize;
    if cpu >= MAX {
        return;
    }
    let now = now_ns();
    let (tid, sys, run) = current_snapshot();
    HB_TID[cpu].store(tid, Ordering::Relaxed);
    HB_SYS[cpu].store(sys, Ordering::Relaxed);
    HB_RUN[cpu].store(run, Ordering::Relaxed);
    HB_STUCK[cpu].store(false, Ordering::Relaxed); // alive ⇒ clear latch
    HB_NS[cpu].store(now, Ordering::Relaxed);
    HB_SEEN[cpu].store(true, Ordering::Relaxed);
    HB_TICKS[cpu].fetch_add(1, Ordering::Relaxed);

    let last = LAST_SCAN_NS.load(Ordering::Relaxed);
    if now.wrapping_sub(last) >= SCAN_INTERVAL_NS
        && LAST_SCAN_NS
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        scan(cpu as u32, now);
        smp_live(now);
    }
}

/// Periodic per-CPU liveness line: ticks taken, nr_running, current tid on
/// every CPU that has ever ticked. Advancing `ticks` + a non-idle `tid` on a
/// secondary CPU is the observable proof that work runs there.
/// # C: O(MAX)
#[cfg(feature = "debug-percpu")]
fn smp_live(now: u64) {
    use core::sync::atomic::AtomicU64 as A;
    static LAST: A = A::new(0);
    const P: u64 = 5_000_000_000;
    let last = LAST.load(Ordering::Relaxed);
    if now.wrapping_sub(last) < P { return; }
    if LAST.compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed).is_err() { return; }
    klog::write_raw(b"[SMP-LIVE]");
    for x in 0..MAX {
        if !HB_SEEN[x].load(Ordering::Relaxed) { continue; }
        klog::write_raw(b" cpu");
        klog::write_dec_u64(x as u64);
        klog::write_raw(b"={ticks=");
        klog::write_dec_u64(HB_TICKS[x].load(Ordering::Relaxed));
        klog::write_raw(b" run=");
        klog::write_dec_u64(HB_RUN[x].load(Ordering::Relaxed) as u64);
        klog::write_raw(b" tid=");
        klog::write_dec_u64(HB_TID[x].load(Ordering::Relaxed) as u64);
        klog::write_raw(b" switches=");
        klog::write_dec_u64(nr_switches(x as u32));
        if HB_IDLE[x].load(Ordering::Relaxed) { klog::write_raw(b" idle"); }
        klog::write_raw(b"}");
    }
    klog::write_raw(b"\n");
}
/// # C: O(1)
#[cfg(not(feature = "debug-percpu"))]
fn smp_live(_now: u64) {}

/// `rq(cpu)->nr_switches` read cross-CPU (0 when that CPU has no runqueue).
/// # C: O(1)
#[cfg(all(feature = "debug-percpu", target_os = "oxide-kernel"))]
fn nr_switches(cpu: u32) -> u64 {
    // SAFETY: `global_for` is sound for any index and yields `None` before
    // `install_global`; the counter is a lock-free relaxed atomic.
    match unsafe { crate::live::runqueue::global_for(cpu) } {
        Some(rq) => rq.nr_switches.load(Ordering::Relaxed),
        None => 0,
    }
}
/// # C: O(1)
#[cfg(all(feature = "debug-percpu", not(target_os = "oxide-kernel")))]
fn nr_switches(_cpu: u32) -> u64 { 0 }

/// Called by the idle loop immediately before parking in `hlt`/`wfi`, and
/// again the instant the park returns. Linux `touch_softlockup_watchdog` on
/// the idle path: between these two points the CPU is quiescent on purpose,
/// so no heartbeat is owed and no stall may be reported. Everything AFTER the
/// park — including the idle loop's own `schedule()` and balance work — is
/// still covered, because `idle_exit` clears the flag before any of it runs.
/// # SAFETY: lock-free per-CPU atomics; callable from the idle loop.
/// # C: O(1)
pub fn idle_enter() { mark_idle(true); }
/// Counterpart to [`idle_enter`], run the moment the park returns.
/// # C: O(1)
pub fn idle_exit() { mark_idle(false); }

/// # C: O(1)
fn mark_idle(idle: bool) {
    let cpu = this_cpu_id() as usize;
    if cpu >= MAX { return; }
    HB_NS[cpu].store(now_ns(), Ordering::Relaxed);
    HB_STUCK[cpu].store(false, Ordering::Relaxed);
    HB_SEEN[cpu].store(true, Ordering::Relaxed);
    HB_IDLE[cpu].store(idle, Ordering::Release);
}

/// Scan every other online CPU; fire a one-shot report for any wedged one.
/// # C: O(MAX)
fn scan(me: u32, now: u64) {
    for x in 0..MAX {
        if x as u32 == me || !HB_SEEN[x].load(Ordering::Relaxed) {
            continue;
        }

        // saturating, not wrapping: a peer CPU's heartbeat can read a hair
        // AHEAD of our `now` (per-CPU TSC/monotonic skew); wrapping_sub would
        // underflow to ~u64::MAX → a bogus "no heartbeat for 18446744073s"
        // false stall (+ spurious NMI poke). Skew clamps to age 0.
        let age = now.saturating_sub(HB_NS[x].load(Ordering::Relaxed));
        let latched = HB_STUCK[x].load(Ordering::Relaxed);
        // Parked in the idle loop ⇒ not wedged (see `idle_enter`).
        let parked = HB_IDLE[x].load(Ordering::Acquire);
        if should_report_stall(age, latched, parked) {
            HB_STUCK[x].store(true, Ordering::Relaxed);
            report_stall(x as u32, age, me);
            // Try to make the wedged CPU dump its own RIP (x86 NMI / arm
            // FIQ). No-op where unavailable; the report above already
            // names the CPU + last-known task regardless.
            super::nmi::poke_cpu(x as u32);
        }
    }
}

/// Emit the cross-CPU stall report from `me` about `x`. Gated with the
/// rest of the diag emit path; the detection logic above is always-on.
/// # C: O(1)
#[cfg(feature = "debug-watchdog")]
fn report_stall(x: u32, age_ns: u64, me: u32) {
    klog::write_raw(b"\n[CPU-STALL] cpu=");
    klog::write_dec_u64(x as u64);
    klog::write_raw(b" no heartbeat for ");
    klog::write_dec_u64(age_ns / 1_000_000_000);
    klog::write_raw(b"s (seen by cpu=");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b") last: tid=");
    klog::write_dec_u64(HB_TID[x as usize].load(Ordering::Relaxed) as u64);
    klog::write_raw(b" syscall=");
    super::format::emit_syscall(HB_SYS[x as usize].load(Ordering::Relaxed));
    klog::write_raw(b" nr_running=");
    klog::write_dec_u64(HB_RUN[x as usize].load(Ordering::Relaxed) as u64);
    // The snapshot above is `age_ns` STALE by construction — it was taken at
    // the wedged CPU's last tick. These are read LIVE off that CPU's runqueue
    // and preempt state, which nothing about the wedge stops us reading:
    //   `now:` still the same tid  ⇒ that task never left the CPU, so the wedge
    //                                is inside ITS kernel section;
    //         a different tid      ⇒ the CPU switched and re-wedged, so the
    //                                stale `last:` names the wrong task;
    //   a raised HARDIRQ/SOFTIRQ field ⇒ wedged inside an interrupt, not a
    //                                syscall;
    //   `resched=1` with no progress ⇒ the request cannot be acted on.
    // Without this the only other evidence is `[NMI-BT]`'s raw rip, which needs
    // the matching kernel ELF to mean anything (B1476).
    klog::write_raw(b" now: tid=");
    klog::write_dec_u64(live_tid(x) as u64);
    klog::write_raw(b" syscall=");
    super::format::emit_syscall(live_syscall(x));
    klog::write_raw(b" preempt_count=0x");
    klog::write_hex_u64(crate::preempt::preempt_count_on(x as usize) as u64);
    klog::write_raw(b" resched=");
    klog::write_dec_u64(crate::preempt::need_resched_on(x as usize) as u64);
    klog::write_raw(b"\n");
}

/// Live `rq(cpu)->curr` tid (0 when that runqueue is not installed).
/// # C: O(1)
#[cfg(feature = "debug-watchdog")]
fn live_tid(cpu: u32) -> u32 { live_curr(cpu).map_or(0, |t| t.tid) }

/// Live `rq(cpu)->curr`'s last-entered syscall (`u32::MAX` = never entered one,
/// rendered `none`). Never cleared on syscall exit, exactly as the heartbeat
/// snapshot's copy — so this is "the last syscall this task ever made", not
/// "the syscall it is in".
/// # C: O(1)
#[cfg(feature = "debug-watchdog")]
fn live_syscall(cpu: u32) -> u32 {
    live_curr(cpu).map_or(u32::MAX, |t| t.last_syscall_nr.load(Ordering::Relaxed))
}

/// `rq(cpu)->curr`, read cross-CPU. # C: O(1)
#[cfg(all(feature = "debug-watchdog", target_os = "oxide-kernel"))]
fn live_curr(cpu: u32) -> Option<&'static crate::Task> {
    // SAFETY: `global_for` is sound for any index and yields `None` for a CPU
    // that has not completed `install_global`; the read is lock-free and the
    // runqueue owns the `Arc` that keeps the task alive.
    let rq = unsafe { crate::live::runqueue::global_for(cpu) }?;
    // SAFETY: same contract as the heartbeat's own `current_ref` read.
    Some(unsafe { rq.current_ref() })
}
/// # C: O(1)
#[cfg(all(feature = "debug-watchdog", not(target_os = "oxide-kernel")))]
fn live_curr(_cpu: u32) -> Option<&'static crate::Task> { None }
#[cfg(not(feature = "debug-watchdog"))]
fn report_stall(_x: u32, _age_ns: u64, _me: u32) {}

/// Invoke `f(cpu)` for every CPU that has heartbeated (is online +
/// ticking). Used by the sysrq backtrace to poke exactly the live CPUs.
/// # C: O(MAX)
pub fn for_each_seen(mut f: impl FnMut(u32)) {
    for x in 0..MAX {
        if HB_SEEN[x].load(Ordering::Relaxed) {
            f(x as u32);
        }
    }
}

/// sysrq on-demand: dump every seen CPU's heartbeat snapshot + age, so
/// the per-CPU picture is visible even when only a wedge is suspected.
/// # C: O(MAX)
#[cfg(feature = "debug-watchdog")]
pub fn dump_cpus() {
    let now = now_ns();
    // `pc` and `resched` are read LIVE (not from the heartbeat snapshot): a
    // wedged CPU has stopped stamping heartbeats, so its snapshot is stale by
    // exactly the interval that matters. The per-CPU preempt state is a plain
    // array, so this CPU can read the wedged one's current value.
    //
    // The signature to look for: `nr_run 0` everywhere with `resched=1` and a
    // non-zero `pc` on some CPU. `should_resched()` gates on the WHOLE count
    // word, so a leaked HARDIRQ (0x10000) or SOFTIRQ (0x100) field means that
    // CPU is structurally unable to act on the reschedule it was asked for —
    // which presents as "everything idle, nothing runnable, no progress".
    klog::write_raw(b"[sysrq] per-cpu heartbeats:\n  CPU  age_ms  last-tid  last-syscall  nr_run  preempt_count  resched\n");
    let mut any = false;
    for x in 0..MAX {
        if !HB_SEEN[x].load(Ordering::Relaxed) {
            continue;
        }
        any = true;
        // saturating, not wrapping: a peer CPU's heartbeat can read a hair
        // AHEAD of our `now` (per-CPU TSC/monotonic skew); wrapping_sub would
        // underflow to ~u64::MAX → a bogus "no heartbeat for 18446744073s"
        // false stall (+ spurious NMI poke). Skew clamps to age 0.
        let age = now.saturating_sub(HB_NS[x].load(Ordering::Relaxed));
        klog::write_raw(b"  ");
        klog::write_dec_u64(x as u64);
        klog::write_raw(b"    ");
        klog::write_dec_u64(age / 1_000_000);
        klog::write_raw(b"     ");
        klog::write_dec_u64(HB_TID[x].load(Ordering::Relaxed) as u64);
        klog::write_raw(b"  ");
        super::format::emit_syscall(HB_SYS[x].load(Ordering::Relaxed));
        klog::write_raw(b"  ");
        klog::write_dec_u64(HB_RUN[x].load(Ordering::Relaxed) as u64);
        klog::write_raw(b"  0x");
        klog::write_hex_u64(crate::preempt::preempt_count_on(x) as u64);
        klog::write_raw(b"  ");
        klog::write_dec_u64(crate::preempt::need_resched_on(x) as u64);
        klog::write_raw(b"\n");
    }
    if !any {
        klog::write_raw(b"  <no cpu has heartbeated yet>\n");
    }
}
/// # C: O(1)
#[cfg(not(feature = "debug-watchdog"))]
pub fn dump_cpus() {}

// ---- arch glue (kernel-only; host stubs keep the logic host-testable) ----

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn this_cpu_id() -> u32 {
    use hal::CpuOps;
    hal_x86_64::X86CpuOps::current_cpu() as u32
}
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn this_cpu_id() -> u32 {
    use hal::CpuOps;
    hal_aarch64::ArmCpuOps::current_cpu() as u32
}
#[cfg(not(target_os = "oxide-kernel"))]
fn this_cpu_id() -> u32 {
    0
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn now_ns() -> u64 {
    use hal::TimerOps;
    hal_x86_64::X86TimerOps::monotonic_ns().0
}
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn now_ns() -> u64 {
    use hal::TimerOps;
    hal_aarch64::ArmTimerOps::monotonic_ns().0
}
#[cfg(not(target_os = "oxide-kernel"))]
fn now_ns() -> u64 {
    0
}

/// `(current tid, its last syscall nr, this CPU's nr_running)`.
#[cfg(target_os = "oxide-kernel")]
fn current_snapshot() -> (u32, u32, u32) {
    match crate::live::global() {
        Some(rq) => {
            // SAFETY: timer-ISR context on this CPU; current_ref reads
            // refcount-stable fields of the task installed in rq.current.
            let t = unsafe { rq.current_ref() };
            (
                t.tid,
                t.last_syscall_nr.load(Ordering::Relaxed),
                rq.nr_running.load(Ordering::Relaxed),
            )
        }
        None => (0, u32::MAX, 0),
    }
}
#[cfg(not(target_os = "oxide-kernel"))]
fn current_snapshot() -> (u32, u32, u32) {
    (0, u32::MAX, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stall_fires_once_past_threshold() {
        assert!(!newly_stalled(STALL_NS - 1, false)); // not yet
        assert!(newly_stalled(STALL_NS, false)); // fires
        assert!(newly_stalled(STALL_NS + 5_000_000_000, false)); // still would
        assert!(!newly_stalled(STALL_NS, true)); // already latched ⇒ no re-fire
    }

    #[test]
    fn fresh_heartbeat_never_stalls() {
        assert!(!newly_stalled(0, false));
        assert!(!newly_stalled(1_000_000, false));
    }

    /// A CPU parked in its idle loop is silent on purpose. Reporting it was a
    /// pure false positive: the secondary CPU has no work, which is not a
    /// wedge, and Linux does not warn about it either.
    #[test]
    fn an_idle_cpu_is_never_reported_however_stale() {
        assert!(!should_report_stall(STALL_NS, false, true));
        assert!(!should_report_stall(STALL_NS * 100, false, true));
    }

    /// The same staleness on a CPU that is NOT parked idle still fires — the
    /// suppression must not blind the detector to a real hard lockup.
    #[test]
    fn a_stale_non_idle_cpu_is_still_reported_once() {
        assert!(should_report_stall(STALL_NS, false, false));
        assert!(!should_report_stall(STALL_NS, true, false));   // latched
        assert!(!should_report_stall(STALL_NS - 1, false, false)); // not yet
    }
}
