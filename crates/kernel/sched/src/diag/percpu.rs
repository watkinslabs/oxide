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
// Coverage note (honest): this needs a second CPU that is still taking
// timer ticks. aarch64 brings APs fully up (they tick), so a frozen BSP
// is observed by an AP and vice-versa. On x86 the AP currently parks
// (P4 SMP scheduling is gated), so x86 has no second observer yet — the
// on-demand sysrq per-CPU dump + the NMI backtrace (super::nmi) are the
// x86 hooks until the AP is woken as an observer. The detector logic and
// snapshot are arch-neutral and ready for that.

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

    let last = LAST_SCAN_NS.load(Ordering::Relaxed);
    if now.wrapping_sub(last) >= SCAN_INTERVAL_NS
        && LAST_SCAN_NS
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        scan(cpu as u32, now);
    }
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
        if newly_stalled(age, latched) {
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
    klog::write_raw(b"\n");
}
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
}
