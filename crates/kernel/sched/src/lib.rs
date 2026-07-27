// Scheduler — 3-class (RT / Normal-CFS / Idle).
//
// Per docs/13 (FROZEN). Runqueue + class containers + `pick_next_task`
// land here; `schedule()` proper, `wake_up`, IPI, SMP load balance,
// and `timer_tick` ride alongside HAL `Context` in subsequent P1-N
// branches.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod bh;
pub mod cfs;
pub mod clock;
pub mod cmdline;
pub mod cputime;
pub mod cpustat;
pub mod loadavg;
pub mod psi;
pub mod diag;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub mod kthread;
pub mod kstack;
pub mod preempt;
pub mod pid;
pub mod thread_group;
pub mod registry;
pub mod exit;
pub mod personality;
pub mod rlimit;
pub mod rt;
pub mod session;
pub mod runqueue;
pub mod task;
pub mod signum;
pub mod sigaltstack;
pub use signum::{bit_for, clone_exit_signal, Signum};
pub mod wait_select;
mod sigqueue;
pub mod sched_enc;
#[path = "timers/clockid.rs"] pub mod posix_clock;
#[path = "timers/model.rs"] mod timer_model;
#[path = "timers/queue.rs"] mod timer_queue;

// RCU API (`06§3.5`). Read side = preempt aliases here; write/grace side
// re-exported from `sync::rcu` so consumers have one `sched`-level surface.
pub use preempt::{rcu_read_lock, rcu_read_unlock};
pub use sync::{call_rcu, note_qs as rcu_note_qs, rcu_barrier, rcu_process_callbacks, synchronize_rcu};

pub use cfs::CfsRunqueue;
pub use cmdline::argv_to_cmdline;
pub use rt::{RtRunqueue, RT_PRIO_COUNT};
pub use registry::kernel_stack_bytes_snapshot;
pub use runqueue::RunqueueInner;
pub use task::{cap, ArchFpuBuf, Creds, GroupList, PosixTimer, SaHandler, SigActions, SignalPending, SchedClass, SchedPolicy, SigInfo, SleepWake, Task, TaskState, TASK_COMM_LEN, SUID_DUMP_DISABLE, SUID_DUMP_ROOT, SUID_DUMP_USER, RT_QUEUE_CAP, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};

/// Maximum size in bytes of a per-arch HAL `Context` record (per
/// `13§5` + `14§5.2` / `14§6.2`). `Task` carries an opaque buffer
/// of this size; per-arch crates assert at compile-time that their
/// `Context` size does not exceed it. v1 sizes:
/// - x86_64 `ContextX86_64`: 0x40 (64 B)
/// - aarch64 `ContextAArch64`: 0x70 (112 B)
/// 128 leaves headroom for v1.x additions (FPU lazy state ptr,
/// PCID/ASID, KPTI selector) without bumping every release.
pub const ARCH_CTX_SIZE: usize = 128;

/// Opaque per-arch FPU/SIMD state size carried on every Task per
/// `14§7`. Sized to cover the largest per-arch shape:
///   x86_64 FXSAVE area = 512 B
///   aarch64 NEON V regs + FPCR/FPSR = 528 B
/// Plus 16-byte alignment slack. 544 satisfies both with align(16).
pub const ARCH_FPU_SIZE: usize = 4096; // heap-allocated 64-aligned XSAVE area; fits x87+SSE+AVX+AVX512 (~2.7KB) with slack

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

pub type KResult<T> = core::result::Result<T, Error>;

// Kernel-installed `current task` accessor. The per-CPU "current"
// pointer lives in the kernel module (it depends on per-CPU state
// the sched crate doesn't own — gs_base on x86, tpidr_el1 on arm).
// Other workspace crates that need `current()` (security, nscg,
// drivers) consume it through this hook so they don't have to
// import kernel-internal modules.
use core::sync::atomic::{AtomicU64, Ordering};
static CURRENT_HOOK: AtomicU64 = AtomicU64::new(0);
pub type CurrentFn = fn() -> Option<&'static Task>;
pub type AllocationContextFn = fn(&Task, bool);
static ALLOCATION_CONTEXT_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the per-CPU `current` accessor. Called once at boot from
/// the kernel module that owns the per-CPU state.
/// # C: O(1)
pub fn set_current_hook(f: CurrentFn) {
    CURRENT_HOOK.store(f as u64, Ordering::Release);
}

/// Install task-switch allocation-context owner. # C: O(1)
pub fn set_allocation_context_hook(f: AllocationContextFn) {
    ALLOCATION_CONTEXT_HOOK.store(f as u64, Ordering::Release);
}

/// Apply the incoming task's allocator owner at the switch boundary.
/// # C: O(1)
/// # Ctx: preempt-disabled scheduler switch
pub fn install_task_allocation_context(task: &Task, kernel: bool) {
    let raw = ALLOCATION_CONTEXT_HOOK.load(Ordering::Acquire);
    if raw == 0 { return; }
    // SAFETY: set_allocation_context_hook stores only AllocationContextFn.
    let f: AllocationContextFn = unsafe { core::mem::transmute(raw) };
    f(task, kernel);
}

/// Returns the running task on this CPU, or `None` if unset (host
/// tests, pre-init).
/// # C: O(1)
pub fn current() -> Option<&'static Task> {
    let h = CURRENT_HOOK.load(Ordering::Acquire);
    if h == 0 { return None; }
    // SAFETY: h was installed by `set_current_hook` with matching ABI; sched_crate is the only writer.
    let f: CurrentFn = unsafe { core::mem::transmute(h) };
    f()
}

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> {
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}

pub mod affinity;
#[cfg(target_os = "oxide-kernel")]
pub mod cgroup;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub mod oom;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub mod live;

#[cfg(target_os = "oxide-kernel")] pub mod compat;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))] pub mod cred;
#[cfg(target_os = "oxide-kernel")] pub mod falloc;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))] pub mod prctl;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))] mod prctl_set_mm;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))] mod prctl_vma;
#[cfg(target_os = "oxide-kernel")] pub mod membarrier;
#[cfg(target_os = "oxide-kernel")] pub mod proclink;
#[cfg(target_os = "oxide-kernel")] pub mod rseq;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))] pub mod timers;
#[cfg(target_os = "oxide-kernel")] pub mod trace;
pub mod xfer;

/// [D26] Periodic mount-expiry sweep (Linux's `mark_mounts_for_expiry`
/// housekeeping): runs one two-pass grace over every registered expire list so
/// autofs/NFS shrinkable submounts auto-umount in production, not only from
/// tests. Cheap — an empty registry scan when no fs registered an expire list.
/// # C: O(N_lists × N_members)
#[cfg(target_os = "oxide-kernel")]
fn mount_expiry_tick(_now_ns: u64) { let _ = vfs::mount::sweep_expired_mounts(); }

/// B1344: fn(u64) adapter so the arg-less orphan-zombie subreaper can register
/// as a ktimers periodic — moved off the hard-IRQ tick because it takes
/// REG/ZOMBIES/child_sigq/rq.inner plain locks (`06§3.1`).
/// # C: O(N_zombies · N_tasks)
#[cfg(target_os = "oxide-kernel")]
fn reap_orphans_tick(_now_ns: u64) { live::zombies::reap_orphans(); }

/// Register the scheduler's periodic timers (cpu.max bandwidth enforcement +
/// SMP load balance + mount-expiry sweep) with the timer subsystem. Boot, once.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn register_timers() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::AcqRel) { return; }
    const P: u64 = 100_000_000; // 100 ms
    timer::register_periodic(P, cgroup::tick);
    timer::register_periodic(P, live::balance::balance_tick);
    // B1344: zombie subreap (B14) + SO_*TIMEO/alarm deadline walker (F169/B20)
    // run HERE (ktimers process context), NOT in the hard-IRQ tick. They take
    // REG/ZOMBIES/child_sigq plain locks — and reap_orphans→wake_wait4_parent
    // takes the runqueue rq.inner lock — that process context also holds with
    // IRQs enabled; a hard-IRQ handler spinning on such a lock self-deadlocks
    // the CPU (`06§3.1`). tick_wake_expired self-throttles to this 100 ms
    // cadence already, so timeout wakeup latency is unchanged.
    timer::register_periodic(P, reap_orphans_tick);
    timer::register_periodic(P, live::tick_wake_expired);
    // PSI cpu-pressure sampling: also process-context here (its SYS spinlock is
    // held plain by /proc/pressure readers) — never charged from the hard IRQ.
    timer::register_periodic(P, psi::tick);
    // [D26] Low-frequency expiry housekeeping (1 s) — the two-pass grace means
    // an idle shrinkable mount is reaped ~1 sweep after going unused; running it
    // at the bandwidth/balance cadence would be needlessly aggressive.
    const EXPIRE_P: u64 = 1_000_000_000; // 1 s
    timer::register_periodic(EXPIRE_P, mount_expiry_tick);
    // RCU callback drain (`06§3.5`) — bounded fallback drainer. The PRIMARY
    // drain is `ksoftirqd` (process context); this tick guarantees forward
    // progress + leak-safety if ksoftirqd is starved. Cheap when idle.
    const RCU_P: u64 = 10_000_000; // 10 ms
    timer::register_periodic(RCU_P, rcu_drain_tick);
}

/// Timer-tick RCU drain (`06§3.5`). Advances the grace machine + runs any
/// callbacks whose grace period elapsed. `try_lock`'d internally, so it is
/// a no-op if a process-context drainer holds the drain state.
/// # C: O(ready callbacks)
#[cfg(target_os = "oxide-kernel")]
fn rcu_drain_tick(_now_ns: u64) { sync::rcu_process_callbacks(); }

/// Boot anchor / idle loop: `schedule()` (so an IRQ-woken task runs) then
/// hlt/wfi until the next IRQ. The kernel jumps here at the end of boot.
/// # C: O(∞)
#[cfg(target_os = "oxide-kernel")]
pub fn halt_forever() -> ! {
    loop {
        if live::global().is_some() {
            // SAFETY: boot-anchor / idle context; runqueue installed; preempt-off.
            unsafe { live::schedule(); }
            // B5 newidle balance: schedule() returned ⇒ this CPU has nothing
            // runnable (idle was picked). Before parking, pull a task from a
            // busier CPU so we don't idle while another CPU is overloaded
            // (lower latency than the periodic balance tick). No-op on UP.
            // SAFETY: idle context, no runqueue lock held; one rq lock at a time.
            if unsafe { live::balance::newidle_balance() } > 0 {
                continue; // pulled work — loop back so schedule() runs it
            }
        }
        // An idle CPU is not inside a hard IRQ and is not serving a bottom
        // half, so a non-zero HARDIRQ/SOFTIRQ field HERE is a leak that has
        // already happened — and a fatal one, because `should_resched()` gates
        // on the whole word, so this CPU can never take a wakeup again. The
        // check sits at the moment the CPU gives up looking for work, which is
        // the last point the count is still attributable.
        #[cfg(feature = "debug-preempt")] preempt::debug::check_idle(preempt::preempt_count());
        // RCU quiescent state (`06§3.5`): an idle CPU holds no read-side
        // lock — entering idle is a QS (Linux `rcu_idle_enter`). One atomic
        // bump before parking lets a grace period complete on the UP runtime.
        sync::note_qs();
        #[cfg(target_arch = "x86_64")] hal_x86_64::halt();
        #[cfg(target_arch = "aarch64")] hal_aarch64::halt();
    }
}

/// Hosted-test fallback (never reached in tests).
/// # C: O(∞)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn halt_forever() -> ! { core::hint::spin_loop(); loop {} }
