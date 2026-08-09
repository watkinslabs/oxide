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

/// `(event id, cpu, count, data address, faulted-from-user)`.
pub type SampleFn = fn(CpuSw, usize, u64, u64, bool);

static SAMPLE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the perf sampler. # C: O(1)
pub fn set_sample_hook(f: SampleFn) { SAMPLE_HOOK.store(f as *mut (), Ordering::Release); }

/// `perf_sw_event(event_id, nr, regs, addr)` — charge the accumulator, then
/// give every attached sampling event its overflow opportunity.
///
/// Callers must be in a context that may take the perf registry and one ring
/// lock: process context, no runqueue lock held. The context-switch and
/// migration sites charge from inside the runqueue-locked region and therefore
/// still call [`charge`] directly.
/// # C: O(events attached to this context)
pub fn sw_event(kind: CpuSw, cpu: usize, n: u64, addr: u64, user: bool) {
    charge(kind, cpu, n);
    let p = SAMPLE_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: installed via `set_sample_hook` with the `SampleFn` signature;
    // the Acquire load pairs with that setter's Release store and the pointer
    // is a `'static` fn address.
    let f: SampleFn = unsafe { core::mem::transmute::<*mut (), SampleFn>(p) };
    f(kind, cpu, n, addr, user);
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

    #[test]
    fn out_of_range_cpu_is_dropped_not_aliased() {
        let before = read(CpuSw::Migration, 0);
        charge(CpuSw::Migration, MAX_CPUS, 7);
        assert_eq!(read(CpuSw::Migration, 0), before);
        assert_eq!(read(CpuSw::Migration, MAX_CPUS), 0);
    }
}
