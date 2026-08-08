// `membarrier(2)` IPI protocol + per-command work fns. Target-gated: needs the
// live runqueue, the cross-CPU poke and the running task's mm. The rules this
// file applies are decided in the ungated `super::policy` / `super::arch`, so
// they stay hosted-testable (`docs/53`).

use super::{arch, policy};
use super::policy::{Kind, Ready};

use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use syscall::errno::Errno;

/// `OWNER` value meaning "no round in flight".
const OWNER_FREE: u32 = u32::MAX;
/// Spin bound before a stuck round is force-completed + named. Never reached
/// in correct operation; converts a protocol bug into a logged missed barrier
/// instead of a wedged CPU.
const SPIN_CAP: u64 = 1_000_000_000;

/// Logical CPU owning the in-flight round.
static OWNER: AtomicU32 = AtomicU32::new(OWNER_FREE);
/// Bitmask of logical CPUs that must still ACK the in-flight round.
static PENDING: AtomicU64 = AtomicU64::new(0);
/// `Kind::as_u32` of the in-flight round. Published BEFORE `PENDING`, so a
/// target that observes its own bit has necessarily observed the kind that
/// tells it what work the round owes.
static KIND: AtomicU32 = AtomicU32::new(0);

#[inline]
fn this_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Execute this CPU's half of an in-flight membarrier round: a full memory
/// barrier, then clear our ACK bit. Idempotent — a no-op when this CPU is not
/// a target, which is the common case since it is called from the shared
/// resched-IPI arm of both arch dispatchers.
/// # C: O(1)
/// # Ctx: IRQ
pub fn service() {
    let me = this_cpu();
    if me >= 64 { return; }
    let bit = 1u64 << me;
    if PENDING.load(Ordering::Acquire) & bit == 0 { return; }
    // Linux `ipi_mb`. Ordered after the Acquire load above, so every user
    // access this CPU performed before entering the kernel is complete.
    fence(Ordering::SeqCst);
    // The kind was published before `PENDING`, so the Acquire load above
    // already ordered it; every round is at least a full barrier and the
    // stronger kinds add their own work on top.
    match Kind::from_u32(KIND.load(Ordering::Relaxed)) {
        Kind::Mb => {}
        // Linux `ipi_sync_core`: the barrier alone does not discard
        // instructions this CPU already fetched from code the caller rewrote.
        Kind::SyncCore => arch::sync_core(),
        // Linux `ipi_rseq`: force the return-to-user path to evaluate this
        // thread's critical section, so a restartable sequence cannot straddle
        // the barrier. Unlike the preemption-driven abort, this is owed even
        // when the round caused no reschedule at all.
        Kind::Rseq => crate::rseq::force_fixup(),
    }
    PENDING.fetch_and(!bit, Ordering::AcqRel);
}

/// Barrier every online CPU named in `mask` except this one, and wait.
/// `mask` is over-inclusive by design (Linux: an extra IPI is harmless, a
/// missed one is a broken guarantee).
/// # C: O(popcount(targets)) + IPI round trip
/// # Ctx: process (IRQs on)
fn ipi_barrier(mask: u64, kind: Kind) {
    // A SYNC_CORE round owes the CALLING CPU a serializing instruction even
    // when it is the only CPU online — the caller is the thread that rewrote
    // the code it is about to execute. Every other kind is fully implied by
    // the syscall itself when nothing else can be running.
    if cpu::smp::online_count() <= 1 {
        if policy::includes_self(kind) { arch::sync_core(); }
        return;
    }
    // Pin to this CPU: `this_cpu()` must stay valid across publish + wait,
    // and Linux holds `preempt_disable()` across `smp_call_function_many`.
    crate::preempt::preempt_disable();
    let me = this_cpu() as u32;
    let targets = mask & cpu::smp::online_mask() & !(1u64 << me);
    // Linux dispatches a SYNC_CORE round with `on_each_cpu_mask` rather than
    // the many-variant that skips the caller: if we migrate around the barrier
    // and a sibling thread of the same mm takes our place, that thread would
    // otherwise resume having never serialized.
    if policy::includes_self(kind) { arch::sync_core(); }
    if targets != 0 {
        while OWNER
            .compare_exchange(OWNER_FREE, me, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            service();
            core::hint::spin_loop();
        }
        // (a) Linux's leading `smp_mb()`: our pre-call stores must precede
        // the IPI-induced barrier on every target.
        fence(Ordering::SeqCst);
        // Publish the kind first: a target reads it only after an Acquire load
        // of `PENDING` saw its own bit, so this Release store is what makes it
        // visible. Reversing these two lines lets a target run a plain barrier
        // for a SYNC_CORE round and silently drop the guarantee.
        KIND.store(kind.as_u32(), Ordering::Release);
        PENDING.store(targets, Ordering::Release);
        let mut c = 0u32;
        while c < 64 {
            if targets & (1u64 << c) != 0 {
                // SAFETY: `send_resched_ipi` is the boot-installed non-blocking
                // cross-CPU poke (LAPIC ICR / ICC_SGI1R_EL1); `c` is an online
                // logical CPU taken from the online mask above.
                unsafe { let _ = crate::live::send_resched_ipi(c); }
            }
            c += 1;
        }
        let mut spins = 0u64;
        while PENDING.load(Ordering::Acquire) != 0 {
            service();
            core::hint::spin_loop();
            spins = spins.wrapping_add(1);
            if spins > SPIN_CAP {
                // A target never ACKed: the caller's ordering guarantee was
                // not delivered. Named under the liveness-diagnostic feature
                // (`04§3` R06 keeps klog off the steady-state path); the cap
                // itself always applies, so a protocol bug degrades to a
                // logged stall instead of a wedged CPU.
                #[cfg(feature = "debug-watchdog")]
                {
                    klog::kerror!("membarrier: target CPU never ACKed the barrier IPI");
                }
                PENDING.store(0, Ordering::Release);
                break;
            }
        }
        // (c) Linux's trailing `smp_mb()`: remote stores that preceded the
        // IPI must be visible to our post-syscall loads.
        fence(Ordering::SeqCst);
        OWNER.store(OWNER_FREE, Ordering::Release);
    }
    crate::preempt::preempt_enable_no_check();
}

/// `MEMBARRIER_CMD_GLOBAL`. Linux: `synchronize_rcu()` when more than one CPU
/// is online — every CPU passes a quiescent state, hence a full barrier,
/// before the grace period closes.
/// # C: O(grace period) — blocks
/// # Sleeps: yes
pub fn global() -> Result<(), Errno> {
    if cpu::smp::online_count() > 1 { crate::synchronize_rcu(); }
    Ok(())
}

/// `MEMBARRIER_CMD_GLOBAL_EXPEDITED`. Valid from a process that never
/// registered (Linux: "registration is about the intent to receive the
/// barriers").
///
/// Linux narrows the target set with a per-runqueue copy of each mm's
/// membarrier state; we barrier every other ONLINE CPU instead. That is a
/// strict superset of Linux's set, so the guarantee holds — it costs extra
/// IPIs, never a missed barrier, and it avoids a second copy of the mm state
/// that could disagree with the mm itself.
/// # C: O(online CPUs) + IPI round trip
pub fn global_expedited() -> Result<(), Errno> {
    ipi_barrier(u64::MAX, Kind::Mb);
    Ok(())
}

/// `MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED`. Always 0 (Linux).
/// # C: O(1)
pub fn register_global_expedited() -> Result<(), Errno> {
    with_mm(|mm| { mm.membarrier_register_global_expedited(); Ok(()) })
}

/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED` and its SYNC_CORE / RSEQ variants:
/// barrier the CPUs running threads of the caller's mm, doing whatever extra
/// per-CPU work `kind` names. `EPERM` unless the mm registered THAT kind
/// first — a real, observable part of the ABI, not an optimisation.
///
/// Target set is the mm's `mm_cpumask` (the TLB-shootdown sender uses the same
/// word), which over-approximates "CPU currently runs a thread of this mm" by
/// also including lazy-TLB CPUs. Over-inclusion costs a spurious IPI; omission
/// would break the guarantee. `cpu_id >= 0` narrows it to one CPU, which
/// reaches here only via `MEMBARRIER_CMD_FLAG_CPU` on the RSEQ command.
///
/// Threads of the mm that are NOT running take no IPI. For the plain and RSEQ
/// kinds the switch back to them is itself a full barrier and re-evaluates
/// their rseq state; for SYNC_CORE the mm's registration bit makes the
/// context-switch tail serialize (`arch::sync_core_before_usermode`).
/// # C: O(popcount(mm_cpumask)) + IPI round trip
pub fn private_expedited(kind: Kind, cpu_id: i32) -> Result<(), Errno> {
    with_mm(|mm| {
        policy::admit(kind, Ready {
            private:   mm.membarrier_private_expedited_ready(),
            sync_core: mm.membarrier_private_expedited_sync_core_ready(),
            rseq:      mm.membarrier_private_expedited_rseq_ready(),
        })?;
        // `single_user` is left false: this kernel keeps no cheap mm-user
        // count, and claiming one could only skip work the round would
        // otherwise do. `ipi_barrier` still short-circuits the single-CPU
        // case, and the SYNC_CORE carve-out is what must never be skipped.
        if policy::may_skip_round(kind, false, cpu::smp::online_count() <= 1) { return Ok(()); }
        let mut mask = mm.cpumask();
        if cpu_id >= 0 {
            // Linux answers a plain success for a CPU that is out of range or
            // is not running this mm, so a racing hotplug is not an error.
            if !policy::cpu_id_targetable(cpu_id, cpu::MAX_CPUS) { return Ok(()); }
            mask &= 1u64 << cpu_id;
        }
        ipi_barrier(mask, kind);
        Ok(())
    })
}

/// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED` and its SYNC_CORE / RSEQ
/// variants. Always 0; each sets only its own `_READY` bit, so registering one
/// kind never licenses another.
/// # C: O(1)
pub fn register_private_expedited(kind: Kind) -> Result<(), Errno> {
    with_mm(|mm| {
        match kind {
            Kind::Mb       => mm.membarrier_register_private_expedited(),
            Kind::SyncCore => mm.membarrier_register_private_expedited_sync_core(),
            Kind::Rseq     => mm.membarrier_register_private_expedited_rseq(),
        }
        Ok(())
    })
}

/// `MEMBARRIER_CMD_GET_REGISTRATIONS` inputs: `(global, private, sync_core,
/// rseq)`. The caller encodes them into the `MEMBARRIER_CMD_REGISTER_*`
/// bitmask — UAPI numbering is the ABI shim's, not the scheduler's.
/// # C: O(1)
pub fn registrations() -> Result<(bool, bool, bool, bool), Errno> {
    with_mm(|mm| Ok(mm.membarrier_registrations()))
}

/// Run `f` against the current task's mm. A task with no user mm (kernel
/// thread) has nothing to register or barrier; Linux cannot reach these
/// commands without an mm at all.
/// # C: O(1) + cost of `f`
fn with_mm<T>(f: impl FnOnce(&alloc::sync::Arc<vmm::AddressSpace>) -> Result<T, Errno>) -> Result<T, Errno> {
    let cur = crate::live::current().ok_or(Errno::Einval)?;
    // SAFETY: `mm_ref` reads the running task's own mm slot from the task it
    // is executing on; only `execve`/`exit` on THIS task replace it, and
    // neither can run concurrently with this task's own syscall.
    let mm = unsafe { cur.mm_ref() }.ok_or(Errno::Einval)?;
    f(mm)
}
