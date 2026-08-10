// Per-CPU software-event accumulators — the CPU-context half of Linux's
// `perf_sw_event()` counters. A `perf_event_open`
// with `pid == -1` binds to one CPU (`perf_event_alloc` rejects `cpu == -1`
// for a task-less event), so a CPU-context software counter must be summed
// per CPU, not per task; the per-task half lives in `Task::{min_flt, maj_flt,
// nvcsw, nivcsw, nr_migrations}`.

use core::sync::atomic::{AtomicU64, Ordering};

use cpu::MAX_CPUS;

/// Which per-CPU accumulator a software event reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CpuSw {
    /// ns of task execution charged on this CPU (`task_clock` in CPU context).
    #[default]
    ExecNs        = 0,
    MinFlt        = 1,
    MajFlt        = 2,
    ContextSwitch = 3,
    Migration     = 4,
}

const NR_KINDS: usize = 5;

static ACC: [[AtomicU64; MAX_CPUS]; NR_KINDS] =
    [const { [const { AtomicU64::new(0) }; MAX_CPUS] }; NR_KINDS];

/// Charge `n` to `kind` on `cpu`. Out-of-range CPUs are dropped rather than
/// aliased onto slot 0. # C: O(1)
pub fn charge(kind: CpuSw, cpu: usize, n: u64) {
    if cpu >= MAX_CPUS { return; }
    ACC[kind as usize][cpu].fetch_add(n, Ordering::Relaxed);
}

/// Current accumulator value for `kind` on `cpu`. # C: O(1)
pub fn read(kind: CpuSw, cpu: usize) -> u64 {
    if cpu >= MAX_CPUS { return 0; }
    ACC[kind as usize][cpu].load(Ordering::Relaxed)
}

// ---- sampling hook ------------------------------------------------------
//
// Linux's `perf_sw_event()` both advances the counter AND walks the per-CPU
// swevent hash to hand every matching event an overflow opportunity. The walk
// needs `perf_event`, which lives in `fs` — a crate ABOVE the counter sites
// (`mm-pmm`'s fault path) — so it is reached through this hook. Keeping the
// hook next to `charge` is what stops the two halves from growing separate
// notions of which software event id a site is charging.

use core::sync::atomic::AtomicPtr;

mod deferred;
mod notes;
pub use notes::SwitchNote;
mod sysctl;

/// One counter site's `perf_sw_event(event_id, nr, regs, addr)` call, carrying
/// everything the sampler reads out of the reference's `struct pt_regs *regs`:
/// `perf_instruction_pointer(regs)` and `user_mode(regs)`. A site with no trap
/// frame passes `ip: 0` and the record reports it as such, which is what a
/// reference PMU that supplied nothing does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwSite {
    pub kind: CpuSw,
    pub cpu:  usize,
    /// `nr` — how many units of the event this site is charging.
    pub nr:   u64,
    /// `perf_instruction_pointer(regs)`: the trapped PC.
    pub ip:   u64,
    /// `addr` — the faulting data address, `0` where the site has none.
    pub addr: u64,
    /// `user_mode(regs)`, which selects `PERF_RECORD_MISC_USER`/`_KERNEL`.
    pub user: bool,
    /// The task the units were charged to, when that is NOT the task running
    /// when the sampler sees the site.
    ///
    /// The reference has no equivalent because `__perf_sw_event_sched` samples
    /// inline: `current` IS the charged task. A site whose opportunity was
    /// parked and drained later must name the task it was charged to, or the
    /// record is attributed to whoever happens to be running at drain time.
    /// `None` means "the current task", which is what every inline site is.
    pub charged: Option<Charged>,
}

/// A charged task's identity, carried across a deferral.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Charged { pub pid: u32, pub tid: u32 }

pub type SampleFn = fn(&SwSite);

/// `perf_event_switch(task, next_prev, sched_in)` — `(cpu, note)`. Separate
/// from [`SampleFn`] because a `PERF_RECORD_SWITCH` is a side-band record, not
/// a counter overflow: it is emitted for `attr.context_switch` events whether
/// or not anything is sampling.
pub type SwitchFn = fn(usize, notes::SwitchNote);

static SWITCH_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the `PERF_RECORD_SWITCH` emitter. # C: O(1)
pub fn set_switch_hook(f: SwitchFn) { SWITCH_HOOK.store(f as *mut (), Ordering::Release); }

/// Park this switch's two identities and the instant it happened, for the tail
/// to act on. Called from inside the runqueue-locked region, which is the only
/// place both sides are known.
///
/// `ts` is the switch's own monotonic timestamp — the scheduler has it in hand
/// already, having just charged the outgoing task's slice with it. It travels
/// with the note because the tail closes the outgoing thread's counting window
/// and opens the incoming thread's, and both must be stamped at the switch
/// rather than at the drain.
/// # C: O(1)
pub fn note_switch(cpu: usize, prev_pid: u32, prev_tid: u32, next_pid: u32,
                   next_tid: u32, preempt: bool, ts: u64)
{
    notes::park(cpu, notes::SwitchNote {
        prev_pid, prev_tid, next_pid, next_tid, preempt, ts });
    softirq::raise(softirq::Slot::PerfDeferred);
}

static SAMPLE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the perf sampler. # C: O(1)
pub fn set_sample_hook(f: SampleFn) { SAMPLE_HOOK.store(f as *mut (), Ordering::Release); }

/// Hand `site` to the installed sampler without touching the accumulator —
/// `perf_swevent_event()` alone. The deferred drain uses this because the
/// charge already happened inside the locked region. # C: O(events)
pub fn sample_only(site: &SwSite) {
    let p = SAMPLE_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: installed via `set_sample_hook` with the `SampleFn` signature;
    // the Acquire load pairs with that setter's Release store and the pointer
    // is a `'static` fn address.
    let f: SampleFn = unsafe { core::mem::transmute::<*mut (), SampleFn>(p) };
    f(site);
}

/// `perf_sw_event(event_id, nr, regs, addr)` — charge the accumulator, then
/// give every attached sampling event its overflow opportunity.
///
/// Callers must be in a context that may take the perf registry and one ring
/// lock: process context, no runqueue lock held. Sites inside the
/// runqueue-locked region use [`charge_deferred`] instead.
/// # C: O(events attached to this context)
pub fn sw_event(site: &SwSite) {
    charge(site.kind, site.cpu, site.nr);
    sample_only(site);
}

/// The runqueue-locked form: charge now, take the sampling opportunity at the
/// next [`drain_deferred`].
///
/// The reference takes it inline — `perf_event_task_sched_out`/`_in` both run
/// under `rq->lock`, which its RCU swevent hlist and lockless ring reservation
/// tolerate. oxide's registry and ring are both spinlocked and rank below the
/// runqueue, so the opportunity moves to the first point after the switch where
/// the lock is gone (`finish_task_switch`, which is where the reference already
/// runs the rest of its per-switch perf work). Same CPU, same task, once per
/// switch — only the instant differs.
/// # C: O(1)
pub fn charge_deferred(kind: CpuSw, cpu: usize, n: u64, pid: u32, tid: u32) {
    charge(kind, cpu, n);
    deferred::queue(kind, cpu, n, pid, tid);
    softirq::raise(softirq::Slot::PerfDeferred);
}

/// Install the bottom half that runs the parked opportunities. Called once from
/// kernel init, alongside the sample hook. # C: O(1)
pub fn init_softirq() {
    softirq::set_handler(softirq::Slot::PerfDeferred, || drain_deferred(softirq::this_cpu()));
}

/// Run every sampling opportunity [`charge_deferred`] parked on `cpu`.
///
/// Runs from the `PerfDeferred` softirq, never from the switch tail: the
/// sampler's call chain is deep (a record buffer plus the ring), and the stack
/// gate charges every path that can block for the whole cost of `schedule()`,
/// so hanging it off `finish_task_switch` put 34 syscall paths within 1.4 KiB
/// of the guard page. A bottom half is also what the reference uses
/// (`irq_work_queue`), for the same reason: the work must not run in the
/// context that generated it.
/// # C: O(pending kinds × events)
pub fn drain_deferred(cpu: usize) {
    deferred::drain(cpu, |c| {
        // A scheduler-internal site has no trap frame and no data address; the
        // reference passes `regs = NULL, addr = 0` from the very same place
        // (`__perf_sw_event_sched(..., 1, 0)`), and `perf_swevent_get_recursion_
        // context`'s caller then samples with `regs` synthesised as the current
        // kernel context.
        //
        // The identity, though, is the CHARGED task's and not `current`'s: this
        // drain runs after the switch that charged it, so `current` is by now
        // somebody else.
        sample_only(&SwSite { kind: c.kind, cpu, nr: c.nr, ip: 0, addr: 0, user: false,
                              charged: Some(Charged { pid: c.pid, tid: c.tid }) });
    });
    let p = SWITCH_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: installed via `set_switch_hook` with the `SwitchFn` signature;
    // the Acquire load pairs with that setter's Release store and the pointer
    // is a `'static` fn address.
    let f: SwitchFn = unsafe { core::mem::transmute::<*mut (), SwitchFn>(p) };
    // EVERY parked note, oldest first. Each one closes one thread's counting
    // window and opens another's, so a drain that took only the newest would
    // leave every skipped switch's outgoing thread counting an interval it did
    // not run.
    while let Some(note) = notes::take(cpu) { f(cpu, note); }
}

// The perf sysctl cells (`kernel.perf_event_*`) live in `perf_sw/sysctl.rs`.
pub use sysctl::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_is_per_cpu_and_per_kind() {
        let before0 = read(CpuSw::MinFlt, 0);
        let before1 = read(CpuSw::MinFlt, 1);
        let other   = read(CpuSw::MajFlt, 0);
        charge(CpuSw::MinFlt, 0, 3);
        assert_eq!(read(CpuSw::MinFlt, 0), before0 + 3);
        assert_eq!(read(CpuSw::MinFlt, 1), before1);
        assert_eq!(read(CpuSw::MajFlt, 0), other);
    }

    /// `SAMPLE_HOOK` is one global, so the tests that install one run in turn
    /// rather than racing each other's hook out of the slot.
    static HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn hook_serial() -> std::sync::MutexGuard<'static, ()> {
        HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The runqueue-locked sites must still reach the sampler. Before the
    /// deferral they called `charge` alone, so `PERF_COUNT_SW_CONTEXT_SWITCHES`
    /// and `_CPU_MIGRATIONS` counted but never sampled.
    #[test]
    fn a_runqueue_locked_charge_still_reaches_the_sampler() {
        let _serial = hook_serial();
        use core::sync::atomic::AtomicU64;
        static SEEN_CTXSW: AtomicU64 = AtomicU64::new(0);
        static SEEN_MIGRATION: AtomicU64 = AtomicU64::new(0);
        static SEEN_IP: AtomicU64 = AtomicU64::new(!0);
        fn hook(s: &SwSite) {
            match s.kind {
                CpuSw::ContextSwitch => { SEEN_CTXSW.fetch_add(s.nr, Ordering::Relaxed); }
                CpuSw::Migration     => { SEEN_MIGRATION.fetch_add(s.nr, Ordering::Relaxed); }
                _ => {}
            }
            SEEN_IP.store(s.ip, Ordering::Relaxed);
        }
        set_sample_hook(hook);
        let cpu = 5;
        drain_deferred(cpu);
        SEEN_CTXSW.store(0, Ordering::Relaxed);
        SEEN_MIGRATION.store(0, Ordering::Relaxed);

        let before = read(CpuSw::ContextSwitch, cpu);
        charge_deferred(CpuSw::ContextSwitch, cpu, 1, 7, 9);
        charge_deferred(CpuSw::Migration, cpu, 1, 7, 9);
        // The counter advances at the charge, as it always did.
        assert_eq!(read(CpuSw::ContextSwitch, cpu), before + 1);
        // ...and the sampler has not run yet: the caller still holds the lock.
        assert_eq!(SEEN_CTXSW.load(Ordering::Relaxed), 0);

        // The opportunity is queued as a BOTTOM HALF, not run in the switch
        // tail: the sampler's frames must not be charged to every path that
        // can block. No assertion here — `softirq::pending()` is a global
        // any-slot flag that other tests in this binary also set, so a check
        // on it could not go red if the raise were removed. The gate that
        // CAN fail for this is `make stack-gate`, which is what caught the
        // switch-tail version (34 syscall paths within 1.4 KiB of the guard
        // page) and passes with the bottom half.
        drain_deferred(cpu);
        assert_eq!(SEEN_CTXSW.load(Ordering::Relaxed), 1);
        assert_eq!(SEEN_MIGRATION.load(Ordering::Relaxed), 1);
        // A scheduler site has no trap frame, so it reports no instruction
        // pointer rather than a fabricated one.
        assert_eq!(SEEN_IP.load(Ordering::Relaxed), 0);

        // A second drain with nothing parked fires nothing.
        drain_deferred(cpu);
        assert_eq!(SEEN_CTXSW.load(Ordering::Relaxed), 1);
        SAMPLE_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    }

    /// A parked opportunity names the task it was CHARGED to, not whoever is
    /// running when the drain finally takes it.
    ///
    /// The drain here runs long after the charge, from a context that is not
    /// task 9 at all — which is precisely the live case: the `PerfDeferred`
    /// softirq fires after the switch, so `current` is the INCOMING task while
    /// the context-switch charge belongs to the outgoing one. Before the
    /// identity was carried across the deferral, the sampler fell back to
    /// `current` and every switch record named the wrong task.
    #[test]
    fn a_deferred_charge_names_the_task_it_was_charged_to() {
        let _serial = hook_serial();
        use core::sync::atomic::AtomicU64;
        static SEEN: AtomicU64 = AtomicU64::new(!0);
        fn hook(s: &SwSite) {
            if let Some(c) = s.charged { SEEN.store((c.pid as u64) << 32 | c.tid as u64, Ordering::Relaxed); }
            else { SEEN.store(!0, Ordering::Relaxed); }
        }
        set_sample_hook(hook);
        let cpu = 11;
        drain_deferred(cpu);

        charge_deferred(CpuSw::ContextSwitch, cpu, 1, 700, 900);
        drain_deferred(cpu);
        assert_eq!(SEEN.load(Ordering::Relaxed), 700 << 32 | 900,
                   "the drain reported the charged task's identity");

        // Two tasks charging the same CPU between drains keep their own
        // identities rather than being merged into one.
        charge_deferred(CpuSw::ContextSwitch, cpu, 1, 700, 900);
        charge_deferred(CpuSw::ContextSwitch, cpu, 1, 800, 901);
        drain_deferred(cpu);
        assert_eq!(SEEN.load(Ordering::Relaxed), 800 << 32 | 901,
                   "the last drained charge is the second task's, not a merge");

        // An INLINE site still carries no identity: `current` is the charged
        // task there, and fabricating one would be the opposite defect.
        sw_event(&SwSite { kind: CpuSw::MinFlt, cpu, nr: 1, ip: 0, addr: 0,
                           user: false, charged: None });
        assert_eq!(SEEN.load(Ordering::Relaxed), !0);
        SAMPLE_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    }

    #[test]
    fn out_of_range_cpu_is_dropped_not_aliased() {
        let before = read(CpuSw::Migration, 0);
        charge(CpuSw::Migration, MAX_CPUS, 7);
        assert_eq!(read(CpuSw::Migration, 0), before);
        assert_eq!(read(CpuSw::Migration, MAX_CPUS), 0);
    }
}
