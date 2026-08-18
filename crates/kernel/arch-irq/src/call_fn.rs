// x86 cross-CPU function call — the arch half of `hal::smp_call`.
//
// ONE vector, ONE queue, ONE drain. The vector formerly named
// `VEC_TLB_SHOOTDOWN` is now `VEC_CALL_FUNCTION` and carries every cross-CPU
// request; TLB shootdown is a caller of this file rather than a protocol
// beside it, which is how the reference is arranged (it has no private TLB
// vector: its remote flush goes through the ordinary call-function queue).
// A second vector with its own in-flight bookkeeping would be a parallel
// mechanism that could disagree with this one about who has acknowledged
// what, which is exactly the class of split this project forbids.
//
// WHAT CHANGED FROM THE SINGLE-SLOT SHOOTDOWN. The old protocol had one
// global in-flight slot guarded by an owner CAS, plus a round id so a late
// acknowledgement could not be credited to the next round. Both existed to
// simulate a property the reference gets structurally: a per-(sender,
// target) call descriptor that a second call cannot reuse until the first
// has completed. `cpu::call_fn::CallQueues` provides exactly that, so the
// owner lock and the round id are gone and two CPUs may now have calls
// outstanding to a third simultaneously.
//
// LIVENESS — the honest statement, unchanged in substance. The reference
// requires the SENDER to have interrupts enabled and no path of its own
// spins unboundedly with interrupts off, so every target reaches its IPI.
// Oxide syscall work and process faults run IRQ-on, but a target inside an
// explicit atomic section still cannot take the IPI — so every lock spin in
// `sync` drains this queue (`set_spin_relax_hook`), and a wait that takes
// too long warns, re-sends the IPI and NMI-backtraces the stuck CPU exactly
// as the reference's stuck-call handling does. It NEVER gives up: abandoning
// the wait and letting the caller free the resource is a use-after-free on a
// peer, which is strictly worse than a loud hang.

#![cfg(target_os = "oxide-kernel")]

use cpu::call_fn::{drop_unreachable, escalation_due, escalation_gap, targets_for, CallQueues};
use hal::smp_call::CallKind;
use hal::{CpuOps, MmuOps, TimerOps, Va};

/// The one cross-CPU call state for the machine.
static QUEUES: CallQueues = CallQueues::new();

/// Escalation base: warn + re-send the IPI + NMI-backtrace the stuck CPU.
/// Matches the reference's stuck-call timeout of 5000 ms. Repeats back off
/// from here via `escalation_gap`, as the reference's do.
const STUCK_WARN_NS: u64 = 5_000_000_000;
/// Clock-free equivalent, used only while the TSC is uncalibrated
/// (`monotonic_ns()` still reports 0) and the spin count is the only measure.
const STUCK_WARN_SPINS: u64 = 500_000_000;

#[inline]
fn this_cpu() -> usize {
    (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1)
}

/// Run one queued call on this CPU.
///
/// Every arm must take no lock, never sleep, and be safe to run from a lock
/// spin — see the contract on `hal::smp_call::CallKind`.
fn exec(kind: u32, arg: u64) {
    match CallKind::from_u32(kind) {
        Some(CallKind::TlbFlush) => {
            // SAFETY: local TLB invalidate; legal at CPL=0. `arg` is the VA
            // the sender published, or the ALL sentinel for a full flush.
            unsafe {
                if arg == hal::smp_call::ALL {
                    <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::flush_all_local();
                } else {
                    <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::flush_va(Va(arg));
                }
            }
        }
        Some(CallKind::LdtReload) => sched::ldt::flush_ldt_remote(arg),
        Some(CallKind::MembarrierGlobalMb) => sched::membarrier::service_global(),
        Some(CallKind::MembarrierPrivateMb) => sched::membarrier::service_private_mb(arg),
        Some(CallKind::MembarrierPrivateSyncCore) => sched::membarrier::service_private_sync_core(arg),
        Some(CallKind::MembarrierPrivateRseq) => sched::membarrier::service_private_rseq(arg),
        Some(CallKind::CpuFreq) => firmware::acpi::cpufreq::service_remote(arg),
        Some(CallKind::Stop) => {
            // Publish BEFORE parking: the waiter frees nothing, but it does
            // proceed to overwrite the pages this CPU was running out of, so
            // the bit must mean "already stopped", never "about to".
            hal::smp_call::mark_stopped(this_cpu() as u32);
            loop {
                // SAFETY: terminal park; `hlt` is legal at CPL 0 and this CPU
                // runs no further kernel code — the machine is on its way to a
                // different kernel.
                unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
            }
        }
        // A slot that decodes to no kind cannot be executed and must not be
        // guessed at; the drain still releases it, so the sender proceeds.
        None => {}
    }
}

/// Drain every call queued for this CPU.
///
/// Called from the call-function IPI dispatch AND from every lock spin in
/// `sync` (so a CPU waiting for a lock still services the CPU that may be
/// holding it — the deadlock-breaker). Idempotent: a no-op when this CPU has
/// nothing queued.
/// # C: O(queued entries)
pub fn service() {
    QUEUES.drain(this_cpu(), exec);
}

/// Send the call-function IPI to one logical CPU. Returns false when the
/// logical id has no hardware id — nothing was sent, so the caller must not
/// wait on it.
/// # SAFETY: LAPIC enabled.
unsafe fn send_ipi(logical_cpu: u32) -> bool {
    let apic = match cpu::hardware_id_for_logical(logical_cpu).and_then(|id| u32::try_from(id).ok()) {
        Some(a) => a,
        None => return false,
    };
    let lo = crate::lapic::build_icr_lo(hal_x86_64::VEC_CALL_FUNCTION, 0b000, true, false);
    // SAFETY: serialize prior ICR write, then deliver the fixed IPI.
    unsafe {
        crate::lapic::wait_icr_idle();
        let _ = crate::lapic::write_icr(apic, lo);
        crate::lapic::wait_icr_idle();
    }
    true
}

/// The `hal::smp_call` hook: run `kind`/`arg` on every online CPU in `mask`
/// except this one, waiting for completion when `wait` is set.
///
/// No-op when only this CPU is online (UP / pre-AP boot) or when `mask` names
/// no other CPU — the common single-threaded-process case, which costs zero
/// IPIs.
/// # C: O(popcount(targets)) + IPI round-trip
fn call_function_many(mask: &[u64], kind: u32, arg: u64, wait: bool) {
    if cpu::smp::online_count() <= 1 { return; }
    let me = this_cpu();
    let targets = targets_for(cpu::CpuMask::from_words(mask), cpu::smp::online_cpumask(), me);
    if targets.is_empty() { return; }

    let mut pending = targets;
    let mut c = 0usize;
    while c < cpu::MAX_CPUS {
        if targets.contains(c) {
            let t = c;
            // Take this sender's descriptor for `t`, draining our own queue
            // while a previous call on it is outstanding: without that, two
            // CPUs each waiting to send to the other never progress.
            QUEUES.lock_slot(me, t, || {
                service();
                sync::spin_relax::relax();
            });
            let need_ipi = QUEUES.push(me, t, kind, arg);
            // SAFETY: LAPIC enabled post-boot; target is an online CPU.
            if need_ipi && !unsafe { send_ipi(c as u32) } {
                // Never delivered. The entry is queued but nothing will drain
                // it, so waiting is a hang for an acknowledgement that cannot
                // arrive — and a CPU with no hardware id was never scheduled
                // on, so it holds no stale state.
                pending = drop_unreachable(pending, c as u32);
            }
        }
        c += 1;
    }

    if !wait { return; }
    wait_for(me, pending);
}

/// Wait until every target in `pending` has finished running the call.
///
/// The wait is unconditional, like the reference's: declaring the call missed
/// and returning would let the caller free a page a peer still has a live
/// translation for, or a descriptor table a peer's LDTR still names.
fn wait_for(me: usize, pending: cpu::CpuMask) {
    let t0 = now_ns();
    let mut fired: u32 = 0;
    let mut next_warn = t0.wrapping_add(STUCK_WARN_NS);
    let mut spins: u64 = 0;
    let mut next_spin_warn = STUCK_WARN_SPINS;
    loop {
        let mut left = cpu::CpuMask::empty();
        let mut c = 0usize;
        while c < cpu::MAX_CPUS {
            if pending.contains(c) && !QUEUES.is_complete(me, c) {
                let _ = left.insert(c);
            }
            c += 1;
        }
        if left.is_empty() { return; }
        // Service our own queue: the CPU we are waiting for may in turn be
        // waiting for us.
        service();
        sync::spin_relax::relax();
        spins = spins.wrapping_add(1);
        let now = now_ns();
        if escalation_due(now, next_warn, spins, next_spin_warn) {
            report_stuck(me, left, now.wrapping_sub(t0), spins);
            fired = fired.saturating_add(1);
            next_warn = now.wrapping_add(escalation_gap(STUCK_WARN_NS, fired));
            next_spin_warn = spins.wrapping_add(escalation_gap(STUCK_WARN_SPINS, fired));
        }
    }
}

/// Monotonic ns. One reader of the arch clock for this file.
/// # C: O(1)
#[inline]
fn now_ns() -> u64 { hal_x86_64::X86TimerOps::monotonic_ns().0 }

/// Matches the reference's stuck-call handling: name the CPUs that still owe
/// completion, re-send the IPI in case it was lost, and NMI-backtrace them so
/// the blocking kernel section is identified rather than inferred. Non-fatal
/// — the wait continues.
/// # C: O(popcount(left))
#[cold]
fn report_stuck(me: usize, left: cpu::CpuMask, waited_ns: u64, spins: u64) {
    klog::write_raw(b"[SMPCALL-STUCK] cpu=");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" waited_ms=");
    klog::write_dec_u64(waited_ns / 1_000_000);
    klog::write_raw(b" spins=");
    klog::write_dec_u64(spins);
    klog::write_raw(b" pending=");
    klog::write_hex_u64(left.low_word());
    klog::write_raw(b"\n");
    let mut c = 0usize;
    while c < cpu::MAX_CPUS {
        if left.contains(c) {
            // SAFETY: LAPIC enabled post-boot; re-delivering the same fixed
            // vector to a CPU that still owes completion is idempotent
            // (`service()` is a no-op once its queue is empty).
            unsafe { let _ = send_ipi(c as u32); }
            sched::diag::nmi::poke_cpu(c as u32);
        }
        c += 1;
    }
}

/// Install the x86 cross-CPU call implementation into the `hal::smp_call`
/// hook. Call once at boot AFTER AP bring-up and once the call-function IDT
/// vector is live.
/// # SAFETY: boot path; single in-flight install; LAPIC up on all CPUs.
/// # C: O(1)
pub unsafe fn install() {
    // SAFETY: boot path; `call_function_many` lives for the kernel lifetime.
    unsafe { hal::smp_call::set_call_hook(call_function_many); }
    // Every spin in `sync` now services pending cross-CPU calls, which is
    // what makes this protocol's liveness claim true rather than assumed: a
    // CPU spinning for a lock with interrupts masked would otherwise never
    // take the IPI, and the sender (often the very CPU holding that lock)
    // would wait forever.
    // SAFETY: `service` takes no locks, and every call kind it can run is
    // bound by the same contract, so it meets the reentrancy requirement
    // `set_spin_relax_hook` imposes — it is already called from IRQ context.
    unsafe { sync::set_spin_relax_hook(service); }
}
