// `membarrier(2)` work fns — Linux `kernel/sched/membarrier.c`.
//
// WHAT THE EXPEDITED COMMANDS ACTUALLY NEED. Linux's `ipi_mb()` is nothing
// but `smp_mb()`: the ordering comes from the TARGET entering the kernel and
// executing a full barrier, not from a private vector. So the poke rides the
// existing cross-CPU resched IPI (`live::send_resched_ipi` — x86 `VEC_RESCHED`,
// arm `SGI 0`), which is already installed, already enabled on every PE, and
// already delivered through both dispatchers; each dispatcher calls `service()`
// on entry. A spurious `need_resched` on a target is the same cost Linux pays
// for every wake-up IPI, and this needs no new IDT stub / per-redistributor SGI
// enable — the two places an arch-lockstep gap would otherwise open.
//
// PROTOCOL (single in-flight, mirrors `arch-irq::tlb`):
//   sender: fence -> publish PENDING(targets) -> IPI each -> spin till 0 -> fence
//   target: IRQ entry -> `service()`: fence, clear own bit
// The target's fence is ordered AFTER it observed the sender's `PENDING`
// store, which is ordered after the sender's pre-syscall user writes. That is
// exactly the (a)/(b)/(c) pairing the header of Linux's `membarrier.c`
// requires for scenarios (A) and (B).
//
// Callers run in syscall context with IRQs ON, so a target can always take the
// IPI; a second would-be sender spins on `OWNER` while calling `service()`, so
// it still ACKs the in-flight round and sender-vs-sender cannot deadlock.

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
    PENDING.fetch_and(!bit, Ordering::AcqRel);
}

/// Barrier every online CPU named in `mask` except this one, and wait.
/// `mask` is over-inclusive by design (Linux: an extra IPI is harmless, a
/// missed one is a broken guarantee).
/// # C: O(popcount(targets)) + IPI round trip
/// # Ctx: process (IRQs on)
fn ipi_barrier(mask: u64) {
    if cpu::smp::online_count() <= 1 { return; }
    // Pin to this CPU: `this_cpu()` must stay valid across publish + wait,
    // and Linux holds `preempt_disable()` across `smp_call_function_many`.
    crate::preempt::preempt_disable();
    let me = this_cpu() as u32;
    let targets = mask & cpu::smp::online_mask() & !(1u64 << me);
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
    ipi_barrier(u64::MAX);
    Ok(())
}

/// `MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED`. Always 0 (Linux).
/// # C: O(1)
pub fn register_global_expedited() -> Result<(), Errno> {
    with_mm(|mm| { mm.membarrier_register_global_expedited(); Ok(()) })
}

/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED`: barrier the CPUs running threads of
/// the caller's mm. `EPERM` unless the mm registered first — a real,
/// observable part of the ABI, not an optimisation.
///
/// Target set is the mm's `mm_cpumask` (Linux `flush_tlb_others` uses the
/// same word), which over-approximates "CPU currently runs a thread of this
/// mm" by also including lazy-TLB CPUs. `cpu_id >= 0` narrows it to that one
/// CPU; it can only arrive via `MEMBARRIER_CMD_FLAG_CPU`, which is legal on
/// no command this kernel accepts, so in practice `cpu_id` is always -1.
/// # C: O(popcount(mm_cpumask)) + IPI round trip
pub fn private_expedited(cpu_id: i32) -> Result<(), Errno> {
    with_mm(|mm| {
        if !mm.membarrier_private_expedited_ready() { return Err(Errno::Eperm); }
        let mut mask = mm.cpumask();
        if cpu_id >= 0 {
            // Linux returns 0 for an out-of-range / not-running-this-mm CPU.
            if (cpu_id as usize) >= cpu::MAX_CPUS { return Ok(()); }
            mask &= 1u64 << cpu_id;
        }
        ipi_barrier(mask);
        Ok(())
    })
}

/// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED`. Always 0 (Linux).
/// # C: O(1)
pub fn register_private_expedited() -> Result<(), Errno> {
    with_mm(|mm| { mm.membarrier_register_private_expedited(); Ok(()) })
}

/// `MEMBARRIER_CMD_GET_REGISTRATIONS` inputs: `(global_ready, private_ready)`.
/// The caller encodes them into the `MEMBARRIER_CMD_REGISTER_*` bitmask —
/// UAPI numbering is the ABI shim's, not the scheduler's.
/// # C: O(1)
pub fn registrations() -> Result<(bool, bool), Errno> {
    with_mm(|mm| {
        Ok((mm.membarrier_global_expedited_ready(), mm.membarrier_private_expedited_ready()))
    })
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
