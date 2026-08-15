// `membarrier(2)` IPI protocol + per-command work fns. Target-gated: needs the
// live runqueue, the cross-CPU poke and the running task's mm. The rules this
// file applies are decided in the ungated `super::policy` / `super::arch`, so
// they stay hosted-testable (`docs/53`).

use super::{arch, policy};
use super::policy::{Kind, Ready};

use core::sync::atomic::{fence, Ordering};

use syscall::errno::Errno;

/// Serialize whole-machine expedited rounds. The owner may wait for remote
/// CPUs, so this must be a sleeping mutex rather than a spinlock.
static IPI_MUTEX: crate::live::Mutex<()> = crate::live::Mutex::new(());
/// A CPU-targeted round serializes only with another round for that target.
static CPU_IPI_MUTEX: [crate::live::Mutex<()>; cpu::MAX_CPUS] =
    [const { crate::live::Mutex::new(()) }; cpu::MAX_CPUS];

/// True when this CPU is still running the address space selected by a
/// private round. A task can switch after the sender took its mask snapshot;
/// that new task owes nothing, while the old one is covered before it next
/// returns to user mode.
/// # C: O(1)
/// # Ctx: IRQ
fn private_target(root_pa: u64) -> bool {
    let Some(cur) = crate::live::current() else { return false; };
    // SAFETY: an IRQ or spin-relax handler runs against this CPU's current
    // task; that task cannot replace its own mm concurrently with this read.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return false; };
    mm.root_pa() == root_pa
}

/// Run the global expedited barrier for this CPU when its current address
/// space registered the command.
/// # C: O(1)
/// # Ctx: IRQ or spin-relax drain
pub fn service_global() {
    let Some(cur) = crate::live::current() else { return; };
    // SAFETY: this handler cannot switch away from its current task while it
    // observes the task-owned address-space reference.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return; };
    if mm.membarrier_global_expedited_ready() { fence(Ordering::SeqCst); }
}

/// Run the plain private expedited barrier for `root_pa` when it remains
/// current on this CPU.
/// # C: O(1)
/// # Ctx: IRQ or spin-relax drain
pub fn service_private_mb(root_pa: u64) {
    if private_target(root_pa) { fence(Ordering::SeqCst); }
}

/// Run the private expedited core-serialization operation for `root_pa`.
/// # C: O(1)
/// # Ctx: IRQ or spin-relax drain
pub fn service_private_sync_core(root_pa: u64) {
    if !private_target(root_pa) { return; }
    fence(Ordering::SeqCst);
    arch::sync_core();
}

/// Run the private expedited restartable-sequence operation for `root_pa`.
/// # C: O(1)
/// # Ctx: IRQ or spin-relax drain
pub fn service_private_rseq(root_pa: u64) {
    if !private_target(root_pa) { return; }
    fence(Ordering::SeqCst);
    crate::rseq::force_fixup();
}

/// Barrier every online CPU named in `mask` except this one, and wait.
/// `mask` is over-inclusive by design (Linux: an extra IPI is harmless, a
/// missed one is a broken guarantee).
/// # C: O(popcount(targets)) + IPI round trip
/// # Ctx: process (IRQs on)
fn ipi_barrier(mask: cpu::CpuMask, kind: Kind, root_pa: u64, global: bool) {
    // A SYNC_CORE round owes the CALLING CPU a serializing instruction even
    // when it is the only CPU online — the caller is the thread that rewrote
    // the code it is about to execute. Every other kind is fully implied by
    // the syscall itself when nothing else can be running.
    if cpu::smp::online_count() <= 1 {
        if policy::includes_self(kind) { arch::sync_core(); }
        return;
    }
    // Pin to this CPU across queue publication and completion; the generic
    // transport owns the sender descriptor by the current CPU id.
    crate::preempt::preempt_disable();
    let targets = mask.intersect(cpu::smp::online_cpumask());
    // Linux dispatches a SYNC_CORE round with `on_each_cpu_mask` rather than
    // the many-variant that skips the caller: if we migrate around the barrier
    // and a sibling thread of the same mm takes our place, that thread would
    // otherwise resume having never serialized.
    if policy::includes_self(kind) { arch::sync_core(); }
    // The leading and trailing barriers pair caller memory with the target
    // handler; the call transport supplies the completion handoff.
    fence(Ordering::SeqCst);
    let call = if global { hal::smp_call::CallKind::MembarrierGlobalMb }
        else { kind.private_call_kind() };
    hal::smp_call::call_function_many(targets.as_words(), call, root_pa, true);
    fence(Ordering::SeqCst);
    crate::preempt::preempt_enable_no_check();
}

/// Hold the matching sleeping serialization lock across one expedited round.
/// # C: O(1) uncontended + round trip
/// # Sleeps: yes, while another round owns the same serialization domain
fn serialize_ipi(cpu: Option<usize>, f: impl FnOnce()) {
    match cpu {
        Some(cpu) => {
            // SAFETY: membarrier syscalls run in process context before this
            // function; no spinlock or IRQ context reaches this path.
            let _guard = unsafe { CPU_IPI_MUTEX[cpu].lock() };
            f();
        }
        None => {
            // SAFETY: membarrier syscalls run in process context before this
            // function; no spinlock or IRQ context reaches this path.
            let _guard = unsafe { IPI_MUTEX.lock() };
            f();
        }
    }
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
    serialize_ipi(None, || ipi_barrier(cpu::CpuMask::all(), Kind::Mb, 0, true));
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
        let mut mask = mm.cpumask_full();
        if cpu_id >= 0 {
            // Linux answers a plain success for a CPU that is out of range or
            // is not running this mm, so a racing hotplug is not an error.
            if !policy::cpu_id_targetable(cpu_id, cpu::MAX_CPUS) { return Ok(()); }
            mask = mask.intersect(cpu::CpuMask::of(cpu_id as usize));
        }
        let root_pa = mm.root_pa();
        let target_cpu = (cpu_id >= 0).then_some(cpu_id as usize);
        serialize_ipi(target_cpu, || ipi_barrier(mask, kind, root_pa, false));
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
