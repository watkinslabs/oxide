// x86 cross-CPU TLB shootdown (`20§5`). Implements the `hal::tlb` hook.
//
// x86 `invlpg`/CR3-reload flush only the local TLB — there is no
// hardware broadcast (unlike aarch64 `tlbi vae1is`). When a CPU
// downgrades or removes a user PTE, every other CPU running the SAME mm
// keeps the stale translation cached. A peer thread then writes through
// a now-COW-shared frame (write-while-shared corruption) or touches a
// freed/realloc'd frame. Linux's `flush_tlb_others` IPIs the mm's
// cpumask and waits; this is the same, broadcast to all online CPUs.
//
// PROTOCOL (deadlock-free, single in-flight shootdown):
//   * One global slot serialized by `OWNER` (CAS). A second would-be
//     sender, while spinning to acquire `OWNER`, runs `service()` so it
//     ACKs the current owner even with its own IRQs masked — breaking
//     the sender↔sender wait. Targets that are NOT senders ACK via the
//     0x42 IPI as soon as they have IF=1 (every fault/IRQ handler is
//     short and re-enables on iretq), so the owner's wait is bounded.
//   * The owner publishes `SHOOT_VA` + a `PENDING` bitmask of the OTHER
//     online CPUs, IPIs each, then spins until `PENDING == 0`.
//
// The owner's own bit is never in `PENDING`, so its in-loop `service()`
// is a no-op; it just waits for the targets. No frame is freed by a
// caller until `shootdown_others_*` returns, so peers can't race a stale
// mapping against a reused frame.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use hal::{CpuOps, MmuOps, Va};

const OWNER_FREE: usize = usize::MAX;

/// Logical CPU that owns the in-flight shootdown (`OWNER_FREE` = none).
static OWNER: AtomicUsize = AtomicUsize::new(OWNER_FREE);
/// VA to invalidate, or `hal::tlb::ALL` for a full local flush.
static SHOOT_VA: AtomicU64 = AtomicU64::new(0);
/// Bitmask of logical CPUs that must still ACK the in-flight shootdown.
static PENDING: AtomicU64 = AtomicU64::new(0);

#[inline]
fn this_cpu() -> usize {
    (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1)
}

/// Perform the local invalidate this CPU was asked for and clear its ACK
/// bit. Called from the 0x42 IPI dispatch AND from the sender spin loops
/// (so a CPU waiting to become the next sender still services the
/// current one — the deadlock-breaker). Idempotent: a no-op when this
/// CPU has no pending request.
/// # C: O(1) (single-page) or O(local TLB) (full flush)
pub fn service() {
    let me = this_cpu();
    if me >= 64 { return; }
    let bit = 1u64 << me;
    if PENDING.load(Ordering::Acquire) & bit == 0 { return; }
    let va = SHOOT_VA.load(Ordering::Acquire);
    // SAFETY: local TLB invalidate; legal at CPL=0. `va` is the VA the
    // owner published (or the ALL sentinel for a full flush).
    unsafe {
        if va == hal::tlb::ALL {
            <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::flush_all_local();
        } else {
            <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::flush_va(Va(va));
        }
    }
    PENDING.fetch_and(!bit, Ordering::AcqRel);
}

/// Send the 0x42 IPI to one logical CPU. # SAFETY: LAPIC enabled.
unsafe fn send_ipi(logical_cpu: u32) {
    let apic = match cpu::hardware_id_for_logical(logical_cpu) {
        Some(a) => a,
        None => return,
    };
    let lo = crate::lapic::build_icr_lo(hal_x86_64::VEC_TLB_SHOOTDOWN, 0b000, true, false);
    // SAFETY: serialize prior ICR write, then deliver the fixed IPI.
    unsafe {
        crate::lapic::wait_icr_idle();
        let _ = crate::lapic::write_icr(apic, lo);
        crate::lapic::wait_icr_idle();
    }
}

/// The `hal::tlb` hook: invalidate `va` (or ALL) on every OTHER online
/// CPU and wait for completion. The CALLER already flushed its own TLB.
/// No-op when only this CPU is online (UP / pre-AP boot).
/// # C: O(online_cpus) + IPI round-trip
fn shootdown(va: u64) {
    if cpu::smp::online_count() <= 1 { return; }
    let me = this_cpu();
    let targets = cpu::smp::online_mask() & !(1u64 << me);
    if targets == 0 { return; }

    // Acquire the single in-flight slot, servicing any shootdown aimed at
    // us while we wait (breaks sender↔sender deadlock under IRQs-off).
    while OWNER
        .compare_exchange(OWNER_FREE, me, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        service();
        core::hint::spin_loop();
    }

    SHOOT_VA.store(va, Ordering::Release);
    PENDING.store(targets, Ordering::Release);
    let mut c = 0u32;
    while c < 64 {
        if targets & (1u64 << c) != 0 {
            // SAFETY: LAPIC enabled post-boot; target is an online CPU.
            unsafe { send_ipi(c); }
        }
        c += 1;
    }

    // Wait for every target to ACK. service() is a no-op for the owner
    // (its bit isn't in PENDING). A very large safety cap converts a
    // catastrophic protocol bug into a logged missed-flush rather than a
    // permanent hang; it is never reached in correct operation.
    let mut spins: u64 = 0;
    while PENDING.load(Ordering::Acquire) != 0 {
        service();
        core::hint::spin_loop();
        spins = spins.wrapping_add(1);
        if spins > 1_000_000_000 {
            PENDING.store(0, Ordering::Release);
            break;
        }
    }

    OWNER.store(OWNER_FREE, Ordering::Release);
}

/// Install the x86 shootdown implementation into the `hal::tlb` hook.
/// Call once at boot AFTER AP bring-up + IDT 0x42 is live.
/// # SAFETY: boot path; single in-flight install; LAPIC up on all CPUs.
/// # C: O(1)
pub unsafe fn install() {
    // SAFETY: boot path; `shootdown` lives for the kernel lifetime.
    unsafe { hal::tlb::set_shootdown_hook(shootdown); }
}
