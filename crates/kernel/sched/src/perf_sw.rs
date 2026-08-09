// Per-CPU software-event accumulators — the CPU-context half of Linux's
// `perf_sw_event()` counters. A `perf_event_open`
// with `pid == -1` binds to one CPU (`perf_event_alloc` rejects `cpu == -1`
// for a task-less event), so a CPU-context software counter must be summed
// per CPU, not per task; the per-task half lives in `Task::{min_flt, maj_flt,
// nvcsw, nivcsw, nr_migrations}`.

use core::sync::atomic::{AtomicU64, Ordering};

use cpu::MAX_CPUS;

/// Which per-CPU accumulator a software event reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuSw {
    /// ns of task execution charged on this CPU (`task_clock` in CPU context).
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
}

pub type SampleFn = fn(&SwSite);

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
pub fn charge_deferred(kind: CpuSw, cpu: usize, n: u64) {
    charge(kind, cpu, n);
    deferred::queue(kind, cpu, n);
}

/// Run every sampling opportunity [`charge_deferred`] parked on `cpu`. Must be
/// called with no runqueue lock held; the scheduler's `finish_task_switch` tail
/// is the one site. # C: O(pending kinds × events)
pub fn drain_deferred(cpu: usize) {
    deferred::drain(cpu, |kind, nr| {
        // A scheduler-internal site has no trap frame and no data address; the
        // reference passes `regs = NULL, addr = 0` from the very same place
        // (`__perf_sw_event_sched(..., 1, 0)`), and `perf_swevent_get_recursion_
        // context`'s caller then samples with `regs` synthesised as the current
        // kernel context.
        sample_only(&SwSite { kind, cpu, nr, ip: 0, addr: 0, user: false });
    });
}

// ---- perf sysctls -------------------------------------------------------
//
// Linux keeps these as globals next to `perf_event_open`:
//   int sysctl_perf_event_paranoid __read_mostly = 2;
//   int sysctl_perf_event_sample_rate __read_mostly = DEFAULT_MAX_SAMPLE_RATE;
// oxide's `perf_event_open` work-fn lives in the `fs` crate, which `procfs`
// cannot depend on (`fs` depends on `procfs`). Owning the live values here —
// the crate both the syscall path and `/proc/sys/kernel` can see — is what
// keeps `/proc/sys/kernel/perf_event_paranoid` from becoming a dead cell that
// disagrees with the gate `perf_event_open` actually applies.

use core::sync::atomic::AtomicI32;

/// Linux's `sysctl_perf_event_paranoid` initialiser.
pub const PARANOID_DEFAULT: i32 = 2;
/// `DEFAULT_MAX_SAMPLE_RATE`.
pub const SAMPLE_RATE_DEFAULT: i32 = 100_000;

static PARANOID:    AtomicI32 = AtomicI32::new(PARANOID_DEFAULT);
static SAMPLE_RATE: AtomicI32 = AtomicI32::new(SAMPLE_RATE_DEFAULT);

/// # C: O(1)
pub fn paranoid() -> i32 { PARANOID.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_paranoid(v: i32) { PARANOID.store(v, Ordering::Relaxed); }
/// # C: O(1)
pub fn sample_rate() -> i32 { SAMPLE_RATE.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_sample_rate(v: i32) { SAMPLE_RATE.store(v, Ordering::Relaxed); }

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

    /// The runqueue-locked sites must still reach the sampler. Before the
    /// deferral they called `charge` alone, so `PERF_COUNT_SW_CONTEXT_SWITCHES`
    /// and `_CPU_MIGRATIONS` counted but never sampled.
    #[test]
    fn a_runqueue_locked_charge_still_reaches_the_sampler() {
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
        charge_deferred(CpuSw::ContextSwitch, cpu, 1);
        charge_deferred(CpuSw::Migration, cpu, 1);
        // The counter advances at the charge, as it always did.
        assert_eq!(read(CpuSw::ContextSwitch, cpu), before + 1);
        // ...and the sampler has not run yet: the caller still holds the lock.
        assert_eq!(SEEN_CTXSW.load(Ordering::Relaxed), 0);

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

    #[test]
    fn out_of_range_cpu_is_dropped_not_aliased() {
        let before = read(CpuSw::Migration, 0);
        charge(CpuSw::Migration, MAX_CPUS, 7);
        assert_eq!(read(CpuSw::Migration, 0), before);
        assert_eq!(read(CpuSw::Migration, MAX_CPUS), 0);
    }
}
