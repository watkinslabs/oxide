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
// PROTOCOL (single in-flight shootdown, one ROUND at a time):
//   * One global slot serialized by `OWNER` (CAS). A second would-be
//     sender, while spinning to acquire `OWNER`, runs `service()` so it
//     ACKs the current owner even with its own IRQs masked — breaking
//     the sender↔sender wait.
//   * The owner bumps `ROUND`, publishes `SHOOT_VA` + a `PENDING`
//     bitmask of the OTHER online CPUs, IPIs each, then waits until
//     `PENDING == 0`.
//   * `service()` records the round it read and ACKs only THAT round
//     (`PENDING` compare-exchange against the same `ROUND`). Without it a
//     target still inside `service()` when the owner tears the round down
//     can clear its bit in the NEXT round having flushed the PREVIOUS
//     round's VA — the owner then frees a frame the target still has
//     cached. Linux gets this for free from the per-CPU `csd` lock, which
//     a second call to the same CPU cannot reuse until the first
//     completes (`kernel/smp.c` `csd_lock`/`csd_unlock`).
//
// The owner's own bit is never in `PENDING`, so its in-loop `service()`
// is a no-op; it just waits for the targets. No frame is freed by a
// caller until `shootdown_others_*` returns, so peers can't race a stale
// mapping against a reused frame.
//
// LIVENESS — the honest statement. Linux requires the SENDER to have
// interrupts enabled (`kernel/smp.c` `smp_call_function_many_cond`:
// `lockdep_assert_irqs_enabled()`, "Can deadlock when called with
// interrupts disabled"; `arch/x86/mm/tlb.c:flush_tlb_mm_range` asserts the
// same), and no Linux path spins unboundedly with IRQs off, so every target
// reaches its IPI. THIS port runs syscalls (IA32_FMASK masks IF) and faults
// (IDT interrupt gates) at IF=0 end to end, so a target inside a long kernel
// section cannot ACK until it finishes. The wait therefore escalates the way
// Linux's `csd_lock_wait_toolong` does — warn, re-send the IPI, NMI-backtrace
// the stuck CPU — and NEVER gives up: abandoning the round and freeing the
// frame anyway is a use-after-free with a live writable translation on the
// peer, which is strictly worse than a loud hang.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use hal::{CpuOps, MmuOps, TimerOps, Va};

const OWNER_FREE: usize = usize::MAX;

/// Logical CPU that owns the in-flight shootdown (`OWNER_FREE` = none).
static OWNER: AtomicUsize = AtomicUsize::new(OWNER_FREE);
/// VA to invalidate, or `hal::tlb::ALL` for a full local flush.
static SHOOT_VA: AtomicU64 = AtomicU64::new(0);
/// Bitmask of logical CPUs that must still ACK the in-flight shootdown.
static PENDING: AtomicU64 = AtomicU64::new(0);
/// Monotonically increasing round id. A target's ACK names the round it
/// serviced, so a late ACK cannot be credited to a later round.
static ROUND: AtomicU64 = AtomicU64::new(0);

/// Escalation base: warn + re-send the IPI + NMI-backtrace the stuck CPU.
/// Linux `kernel/smp.c` `csd_lock_timeout = 5000` ms. Repeats back off from
/// here via `tlb_round::escalation_gap`, as Linux's do.
const STUCK_WARN_NS: u64 = 5_000_000_000;
/// Clock-free equivalent, used only while the TSC is uncalibrated
/// (`monotonic_ns()` still reports 0) and the spin count is the only measure.
const STUCK_WARN_SPINS: u64 = 500_000_000;

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
    // Retry, not return, when the round advances mid-service. The `ROUND` load
    // precedes the `PENDING` load in program order, so a CPU can pair a stale
    // round id with a fresh pending mask; refusing the ACK and leaving would
    // then hold the new round open until its owner re-sent the IPI. Rounds only
    // advance once every target has ACKed, so this retries at most once per
    // completed round.
    loop {
        let round = ROUND.load(Ordering::Acquire);
        let mut pending = PENDING.load(Ordering::Acquire);
        if pending & bit == 0 { return; }
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
        // ACK only the round that was live when the flush was decided. A plain
        // `fetch_and` would credit whatever round happens to be live now — the
        // owner would then free a frame this CPU never invalidated for.
        let mut stale = false;
        loop {
            if !crate::tlb_round::ack_valid(round, ROUND.load(Ordering::Acquire)) {
                stale = true;
                break;
            }
            if pending & bit == 0 { return; }
            match PENDING.compare_exchange(pending, pending & !bit,
                                           Ordering::AcqRel, Ordering::Acquire) {
                Ok(_)  => return,
                Err(p) => pending = p,
            }
        }
        if !stale { return; }
    }
}

/// Send the 0x42 IPI to one logical CPU. Returns false when the logical id has
/// no hardware id — nothing was sent, so the caller must not wait on it.
/// # SAFETY: LAPIC enabled.
unsafe fn send_ipi(logical_cpu: u32) -> bool {
    let apic = match cpu::hardware_id_for_logical(logical_cpu) {
        Some(a) => a,
        None => return false,
    };
    let lo = crate::lapic::build_icr_lo(hal_x86_64::VEC_TLB_SHOOTDOWN, 0b000, true, false);
    // SAFETY: serialize prior ICR write, then deliver the fixed IPI.
    unsafe {
        crate::lapic::wait_icr_idle();
        let _ = crate::lapic::write_icr(apic, lo);
        crate::lapic::wait_icr_idle();
    }
    true
}

/// The `hal::tlb` hook: invalidate `va` (or ALL) on the CPUs named in
/// `mask` (the owning mm's `cpumask`, Linux `flush_tlb_others`) — minus
/// this CPU and any not-yet-online AP — and wait for completion. The
/// CALLER already flushed its own TLB. No-op when only this CPU is online
/// (UP / pre-AP boot) or when `mask` names no other CPU that has the mm
/// loaded (the common single-threaded-process fault path ⇒ zero IPIs,
/// killing the over-broadcast storm that the old all-online-CPU target
/// caused on every COW fault / mprotect / munmap).
/// # C: O(popcount(targets)) + IPI round-trip
fn shootdown(va: u64, mask: u64) {
    if cpu::smp::online_count() <= 1 { return; }
    let me = this_cpu();
    // Intersect the mm's cpumask with the online set and drop self: a CPU
    // that never loaded this mm has no stale entry to flush, and our own
    // TLB was already flushed by the caller.
    let targets = mask & cpu::smp::online_mask() & !(1u64 << me);
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

    // Publish the round BEFORE the targets: a `service()` that reads this
    // round id is then guaranteed to see the matching VA and pending mask.
    ROUND.store(crate::tlb_round::next_round(ROUND.load(Ordering::Acquire)), Ordering::Release);
    SHOOT_VA.store(va, Ordering::Release);
    PENDING.store(targets, Ordering::Release);
    let mut c = 0u32;
    while c < 64 {
        if targets & (1u64 << c) != 0 {
            // SAFETY: LAPIC enabled post-boot; target is an online CPU.
            // A logical id with no hardware id was never IPI'd, so waiting on
            // it would be a guaranteed hang for an ACK that cannot arrive.
            if !unsafe { send_ipi(c) } { PENDING.store(crate::tlb_round::drop_unreachable(PENDING.load(Ordering::Acquire), c), Ordering::Release); }
        }
        c += 1;
    }

    // Wait for every target to ACK. `service()` is a no-op for the owner (its
    // bit isn't in PENDING); it is here to break the sender<->sender wait.
    //
    // Linux `__csd_lock_wait` (`kernel/smp.c`) is an unconditional `for(;;)`
    // whose `csd_lock_wait_toolong` arm warns, NMI-dumps the stuck CPU and
    // re-sends the IPI. This does the same, for the same reason: the alternative
    // — declare the flush missed and let the caller free the frame — leaves a
    // peer holding a live writable translation into a page the buddy is about to
    // recycle.
    let t0 = now_ns();
    let mut fired: u32 = 0;
    let mut next_warn = t0.wrapping_add(STUCK_WARN_NS);
    let mut spins: u64 = 0;
    let mut next_spin_warn = STUCK_WARN_SPINS;
    while PENDING.load(Ordering::Acquire) != 0 {
        service();
        core::hint::spin_loop();
        spins = spins.wrapping_add(1);
        let now = now_ns();
        if crate::tlb_round::escalation_due(now, next_warn, spins, next_spin_warn) {
            report_stuck(me, now.wrapping_sub(t0), spins);
            fired = fired.saturating_add(1);
            next_warn = now.wrapping_add(crate::tlb_round::escalation_gap(STUCK_WARN_NS, fired));
            next_spin_warn = spins
                .wrapping_add(crate::tlb_round::escalation_gap(STUCK_WARN_SPINS, fired));
        }
    }

    OWNER.store(OWNER_FREE, Ordering::Release);
}

/// Monotonic ns. One reader of the arch clock for this file.
/// # C: O(1)
#[inline]
fn now_ns() -> u64 { hal_x86_64::X86TimerOps::monotonic_ns().0 }

/// Linux `csd_lock_wait_toolong` (`kernel/smp.c`): name the CPUs that owe an
/// ACK, re-send the IPI in case it was lost, and NMI-backtrace them so the
/// blocking kernel section is identified rather than inferred. Non-fatal — the
/// wait continues, exactly as Linux's does.
/// # C: O(popcount(PENDING))
#[cold]
fn report_stuck(me: usize, waited_ns: u64, spins: u64) {
    let pending = PENDING.load(Ordering::Acquire);
    klog::write_raw(b"[TLB-STUCK] cpu=");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" waited_ms=");
    klog::write_dec_u64(waited_ns / 1_000_000);
    klog::write_raw(b" spins=");
    klog::write_dec_u64(spins);
    klog::write_raw(b" pending=");
    klog::write_hex_u64(pending);
    klog::write_raw(b" va=");
    klog::write_hex_u64(SHOOT_VA.load(Ordering::Acquire));
    klog::write_raw(b" round=");
    klog::write_dec_u64(ROUND.load(Ordering::Acquire));
    klog::write_raw(b"\n");
    let mut c = 0u32;
    while c < 64 {
        if pending & (1u64 << c) != 0 {
            // SAFETY: LAPIC enabled post-boot; re-delivering the same fixed
            // vector to a CPU that already owes this round's ACK is idempotent
            // (`service()` is a no-op once the bit is clear).
            unsafe { let _ = send_ipi(c); }
            sched::diag::nmi::poke_cpu(c);
        }
        c += 1;
    }
}

/// Install the x86 shootdown implementation into the `hal::tlb` hook.
/// Call once at boot AFTER AP bring-up + IDT 0x42 is live.
/// # SAFETY: boot path; single in-flight install; LAPIC up on all CPUs.
/// # C: O(1)
pub unsafe fn install() {
    // SAFETY: boot path; `shootdown` lives for the kernel lifetime.
    unsafe { hal::tlb::set_shootdown_hook(shootdown); }
    // Every spin in `sync` now services pending shootdowns, which is what makes
    // this protocol's liveness claim true rather than assumed: a CPU spinning
    // for a lock with interrupts masked would otherwise never take the 0x42 IPI,
    // and the owner (often the very CPU holding that lock) would wait forever.
    // `service` takes no locks and is idempotent, so it meets the hook's
    // no-locks / reentrant contract.
    // SAFETY: `service` takes no locks, touches only this CPU's TLB plus two
    // atomics, and is already called from IRQ context — it satisfies the
    // reentrancy contract `set_spin_relax_hook` requires.
    unsafe { sync::set_spin_relax_hook(service); }
}
