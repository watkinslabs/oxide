// Softirq primitive per docs/45 (DRAFT). Linux-equivalent bottom-half
// runner: ISR / process context calls `raise(slot)` to mark a deferred
// handler pending; `run_pending()` is invoked from the timer-ISR tail
// (after EOI, with IRQs unmasked) and walks the bitmask, calling each
// installed handler. Slots are statically numbered (`Slot::*`) so the
// dispatch is a fixed-size table — no allocation, no dyn, no lock.
//
// Per-CPU model (Linux `irq_stat[]` + per-CPU ksoftirqd)
//   - PENDING / IN_PROGRESS are per-CPU arrays. `raise` sets the bit on the
//     CURRENT CPU; `run_pending` drains ONLY this CPU's mask. There is no
//     global queue and no single-CPU bottleneck — every CPU raises + drains
//     its own work from its own timer/MSI tail and its own ksoftirqd.
//   - IN_PROGRESS[cpu] guards re-entry on that CPU: a nested timer ISR that
//     calls run_pending observes its own CPU's guard set and returns; the
//     outer runner drains the new bits on its next iteration. Other CPUs
//     drain concurrently against their own entries.
//   - run_pending applies Linux's `__do_softirq` restart gate
//     (MAX_SOFTIRQ_RESTART / MAX_SOFTIRQ_TIME / need_resched); leftover work
//     defers to this CPU's ksoftirqd via the `wakeup_softirqd` hook.
//
// Limits
//   - 32 slots (one u32 of pending bits). Bump to u64 + 64 handlers
//     if we exhaust them.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// Softirq slot identifiers. Add new entries at the bottom; never
/// reorder existing variants — handlers index by `as u32`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Slot {
    /// fbcon: drain Console.fb → virtio-gpu transfer + flush. Raised
    /// by `fbcon::kernel::klog_sink` after Console.put.
    FbconFlush = 0,
    /// virtio-input: drain device used-ring + translate events to
    /// VT input. Raised by the virtio-input device IRQ.
    InputDrain = 1,
    /// virtio-net: drain RX queue used-ring + dispatch frames into
    /// the net stack. Raised by the MSI dispatcher on every virtio
    /// MSI fire (shared vector — handler bails if RX queue is empty).
    NetRx = 2,
    /// virtio-vsock: drain RX queue used-ring + dispatch packets into
    /// AF_VSOCK. Raised by the MSI dispatcher; the handler is installed
    /// by the virtio-vsock driver probe.
    VsockRx = 3,
    /// virtio-snd: drain EVENTQ used-ring entries. Raised by the
    /// virtio-snd queue-1 MSI callback.
    SndEvent = 4,
    /// Network namespace final-owner drop: wake the process-context reaper.
    NetNsReap = 5,
    /// Block-device completion bottom half. Virtio and other interrupt-driven
    /// block drivers raise this from their completion IRQ; drivers consume
    /// used-ring entries and wake request owners from process-safe context.
    BlockIo = 6,
}

const N_SLOTS: usize = 32;
const PROCESS_ONLY: u32 = 1u32 << (Slot::NetNsReap as u32);
/// Per-CPU array width (Linux `irq_stat[NR_CPUS]`).
const MAX_CPUS: usize = cpu::MAX_CPUS;

/// Per-CPU pending bitmasks — Linux `irq_stat[cpu].__softirq_pending`. Bit
/// `Slot::* as u32` set on CPU N ⇒ that CPU must run the handler. Each CPU
/// raises and drains ONLY its own entry; there is no global queue. The handler
/// table (`HANDLERS`) stays global — Linux `softirq_vec[]` is shared; only the
/// pending mask + drain state are per-CPU.
static PENDING: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// Migration-safe publication for process-only work raised outside a pinned
/// CPU context. Any ksoftirqd may claim these idempotent slot bits.
static PROCESS_PENDING: AtomicU32 = AtomicU32::new(0);

/// Current logical CPU id (kernel) / 0 (host tests). Same arch glue as
/// `sched::diag::percpu::this_cpu_id`. Clamped to `MAX_CPUS` so a bogus id
/// can never index out of bounds.
#[inline]
fn this_cpu() -> usize {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    let id = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() as usize };
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    let id = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() as usize };
    #[cfg(not(target_os = "oxide-kernel"))]
    let id = 0usize;
    if id >= MAX_CPUS { 0 } else { id }
}

/// Handler table. Slot N's handler in `HANDLERS[N]`; null = unset.
/// Stored as `*mut ()` for AtomicPtr; cast through `fn()` on load.
static HANDLERS: [AtomicPtr<()>; N_SLOTS] = [
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
];

// Re-entry is guarded by the per-CPU `preempt_count` softirq field (Linux
// `in_interrupt()`), checked by the caller `sched::bh::do_softirq` — there is
// no separate flag. `run_pending` below is the pure `__do_softirq` core; it
// runs only inside that bh-accounted bracket.

/// Linux `MAX_SOFTIRQ_RESTART` (`kernel/softirq.c`): restart-pass cap before
/// the drain defers, so a self-re-raising slot (virtio-net `NetRx` re-armed
/// by every RX MSI under a packet flood) can't monopolize the CPU and starve
/// the percpu heartbeat.
const MAX_SOFTIRQ_RESTART: u32 = 10;
/// Linux `MAX_SOFTIRQ_TIME` (`2*HZ/1000` jiffies): the wall-clock ceiling on
/// one drain. Expressed in ticks since oxide's jiffies hook returns ticks.
const MAX_SOFTIRQ_TIME: u64 = 2;

/// Boot-installed scheduler/time hooks. `softirq` is a leaf crate (no `sched`
/// dep — that would cycle); the arch/sched layer installs these at boot, the
/// same pattern as `sched::diag::nmi::set_poke_hook`. Null before install =
/// safe defaults (no resched pending, jiffies 0, no-op wakeup), so the
/// restart loop degrades to the `MAX_SOFTIRQ_RESTART` cap alone pre-boot.
static RESCHED_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static JIFFIES_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static WAKEUP_HOOK:  AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static PROCESS_KICK_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the `need_resched()` peek (non-consuming). # C: O(1)
pub fn set_resched_hook(f: fn() -> bool) { RESCHED_HOOK.store(f as *mut (), Ordering::Release); }
/// Install the jiffies/tick reader. # C: O(1)
pub fn set_jiffies_hook(f: fn() -> u64) { JIFFIES_HOOK.store(f as *mut (), Ordering::Release); }
/// Install `wakeup_softirqd` — the deferral target run when the restart gate
/// trips with work still pending. # C: O(1)
pub fn set_wakeup_hook(f: fn()) { WAKEUP_HOOK.store(f as *mut (), Ordering::Release); }
/// Install the lock-free IRQ kick used when process-only work is published.
/// # C: O(1)
pub fn set_process_kick_hook(f: fn()) {
    PROCESS_KICK_HOOK.store(f as *mut (), Ordering::Release);
}

/// Peek `need_resched` via the installed hook. False (don't yield) if unset.
fn need_resched() -> bool {
    let p = RESCHED_HOOK.load(Ordering::Acquire);
    if p.is_null() { return false; }
    // SAFETY: p stored from a `fn() -> bool` by set_resched_hook; reverse-transmute to that exact ABI before call.
    let f: fn() -> bool = unsafe { core::mem::transmute(p) };
    f()
}
/// Read jiffies/ticks via the installed hook. 0 if unset (time gate inert).
fn jiffies() -> u64 {
    let p = JIFFIES_HOOK.load(Ordering::Acquire);
    if p.is_null() { return 0; }
    // SAFETY: p stored from a `fn() -> u64` by set_jiffies_hook; reverse-transmute to that exact ABI before call.
    let f: fn() -> u64 = unsafe { core::mem::transmute(p) };
    f()
}
/// Fire the deferral hook (Linux `wakeup_softirqd`). No-op if unset.
fn wakeup_softirqd() {
    let p = WAKEUP_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: p stored from a `fn()` by set_wakeup_hook; reverse-transmute to that exact ABI before call.
    let f: fn() = unsafe { core::mem::transmute(p) };
    f();
}

fn kick_process_drainer() {
    let p = PROCESS_KICK_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: p was installed from a `fn()` and remains immutable after boot.
    let f: fn() = unsafe { core::mem::transmute(p) };
    f();
}

/// Diagnostic counters.
pub static RAISES: AtomicU32 = AtomicU32::new(0);
pub static RUNS: AtomicU32 = AtomicU32::new(0);
pub static HANDLER_CALLS: AtomicU32 = AtomicU32::new(0);
/// Times a drain tripped the restart gate and deferred still-pending bits.
pub static DEFERRALS: AtomicU32 = AtomicU32::new(0);

/// Install a handler. Caller passes a `fn()` so we don't need
/// `dyn` (per `07§5` no-dyn-in-kernel rule). One handler per slot;
/// later calls overwrite. Returns the previous handler pointer
/// (as `*mut ()`) so callers can chain if they want.
/// # C: O(1) — atomic store.
pub fn set_handler(slot: Slot, f: fn()) -> *mut () {
    let raw = f as *mut ();
    HANDLERS[slot as usize].swap(raw, Ordering::Release)
}

/// Remove a handler and clear any still-pending work for that slot on every
/// CPU. Drivers call this from remove after stopping publication of new work.
/// # C: O(NR_CPUS)
pub fn clear_handler(slot: Slot) -> *mut () {
    let bit = 1u32 << (slot as u32);
    for pending in PENDING.iter() {
        pending.fetch_and(!bit, Ordering::AcqRel);
    }
    PROCESS_PENDING.fetch_and(!bit, Ordering::AcqRel);
    HANDLERS[slot as usize].swap(core::ptr::null_mut(), Ordering::AcqRel)
}

/// Raise `slot` on THIS CPU — Linux `__raise_softirq_irqoff` / `or_softirq_
/// pending`. The bit lands on the running CPU's mask; that CPU drains it from
/// its own timer/MSI tail or its ksoftirqd. Must run with the CPU pinned (ISR
/// context or IRQs/preempt off) so `this_cpu` is stable, exactly as Linux
/// requires of `raise_softirq_irqoff`.
/// # C: O(1) — atomic fetch_or.
pub fn raise(slot: Slot) {
    PENDING[this_cpu()].fetch_or(1u32 << (slot as u32), Ordering::Release);
    RAISES.fetch_add(1, Ordering::Relaxed);
}

/// Raise a process-only slot without requiring CPU pinning. # C: O(1)
/// # Ctx: any; lock-free, allocation-free, IRQ-safe
pub fn raise_process(slot: Slot) {
    let bit = 1u32 << (slot as u32);
    debug_assert!((bit & PROCESS_ONLY) != 0, "raise_process requires process-only slot");
    let old = PROCESS_PENDING.fetch_or(bit, Ordering::AcqRel);
    RAISES.fetch_add(1, Ordering::Relaxed);
    if old & bit == 0 { kick_process_drainer(); }
}

/// True iff this CPU has a slot pending (Linux `local_softirq_pending()`).
/// # C: O(1)
pub fn pending() -> bool {
    PENDING[this_cpu()].load(Ordering::Acquire) != 0
        || PROCESS_PENDING.load(Ordering::Acquire) != 0
}

/// `__do_softirq` core: drain THIS CPU's pending mask with Linux's restart
/// gate. NOT a public entry point — call `sched::bh::do_softirq` (or
/// `local_bh_enable`), which brackets this in softirq accounting and supplies
/// the `in_interrupt()` re-entry guard.
///
/// # Ctx
/// Runs with IRQs enabled (handlers wait on device IRQ acks) and
/// `in_serving_softirq` set by the caller.
///
/// # SAFETY
/// Caller must run inside `sched::bh`'s softirq-accounted bracket (so re-entry
/// is excluded and `this_cpu` is stable) with IRQs locally enabled.
///
/// # C: O(N_handlers_with_work) per drain pass; bounded by the restart gate.
unsafe fn run_pending_mode(process_context: bool) {
    // This CPU's slot. Stable for the drain: callers (`sched::bh::do_softirq`)
    // run with `in_serving_softirq` set, so preemption/migration is off and
    // `this_cpu` can't change under us. Re-entry is already excluded by the
    // caller's `in_interrupt()` guard — no flag here.
    let c = this_cpu();
    RUNS.fetch_add(1, Ordering::Relaxed);
    // Linux `__do_softirq` restart gate, on THIS CPU's pending mask. A handler
    // that re-raises its own bit (NetRx re-armed by each RX MSI under a packet
    // flood) would otherwise spin this loop forever: the CPU never returns to
    // the timer-ISR tail, the percpu heartbeat goes unstamped, and the
    // hard-lockup watchdog fires. Mirror the kernel exactly — after running the
    // pending set, restart only while `time_before(jiffies, end) &&
    // !need_resched() && --max_restart`; otherwise `wakeup_softirqd()` and
    // return, leaving still-pending bits set for this CPU's ksoftirqd to finish.
    let end = jiffies().wrapping_add(MAX_SOFTIRQ_TIME);
    let mut max_restart = MAX_SOFTIRQ_RESTART;
    loop {
        // `set_softirq_pending(0)` — claim this CPU's set, run each handler.
        let local_bits = PENDING[c].swap(0, Ordering::AcqRel);
        let process_bits = if process_context {
            PROCESS_PENDING.swap(0, Ordering::AcqRel)
        } else {
            PROCESS_PENDING.load(Ordering::Acquire)
        };
        if local_bits == 0 && process_bits == 0 {
            break;
        }
        let local_deferred = if process_context { 0 } else { local_bits & PROCESS_ONLY };
        let process_deferred = !process_context && process_bits != 0;
        if local_deferred != 0 {
            PENDING[c].fetch_or(local_deferred, Ordering::Release);
        }
        if local_deferred != 0 || process_deferred {
            wakeup_softirqd();
        }
        let mut b = if process_context {
            local_bits | process_bits
        } else {
            local_bits & !local_deferred
        };
        while b != 0 {
            let idx = b.trailing_zeros() as usize;
            b &= !(1u32 << idx);
            let raw = HANDLERS[idx].load(Ordering::Acquire);
            if !raw.is_null() {
                HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
                // SAFETY: raw was stored via set_handler which casts a non-null `fn()` through `*mut ()`; reverse-cast restores the original ABI-compatible fn pointer; handlers are responsible for their own safety contracts.
                let f: fn() = unsafe { core::mem::transmute::<*mut (), fn()>(raw) };
                f();
            }
        }
        // Process-only work must leave IRQ-tail immediately for ksoftirqd.
        if local_deferred != 0 || process_deferred { break; }
        // Re-raised on this CPU during the pass? Apply the three-way gate.
        if PENDING[c].load(Ordering::Acquire) == 0
            && PROCESS_PENDING.load(Ordering::Acquire) == 0
        {
            break;
        }
        // `time_before(jiffies, end)` — wrapping-safe signed compare.
        let within_time = (jiffies().wrapping_sub(end) as i64) < 0;
        if within_time && !need_resched() {
            max_restart -= 1;
            if max_restart != 0 {
                continue;
            }
        }
        // Gate tripped with work pending → hand off to THIS CPU's ksoftirqd
        // (Linux `wakeup_softirqd`). The still-pending bits remain set.
        wakeup_softirqd();
        DEFERRALS.fetch_add(1, Ordering::Relaxed);
        break;
    }
}

/// Drain IRQ-tail-safe handlers, deferring process-only slots to ksoftirqd.
/// # SAFETY: caller holds the softirq accounting bracket. # C: O(pending work)
pub unsafe fn run_pending() {
    // SAFETY: caller provides the accounting contract for this IRQ-tail mode.
    unsafe { run_pending_mode(false); }
}

/// Drain all handlers from ksoftirqd process context. # C: O(pending work)
/// # SAFETY: caller holds the softirq accounting bracket in process context.
pub unsafe fn run_pending_process() {
    // SAFETY: caller provides process context and the accounting contract.
    unsafe { run_pending_mode(true); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    static T_HITS: AtomicU32 = AtomicU32::new(0);
    fn t_handler() { T_HITS.fetch_add(1, Ordering::Relaxed); }

    static REARM_HITS: AtomicU32 = AtomicU32::new(0);
    // Mimics an RX softirq re-armed by an MSI mid-drain: re-raises its own
    // bit every pass. Without the restart cap this loops `run_pending` forever.
    fn rearming_handler() {
        REARM_HITS.fetch_add(1, Ordering::Relaxed);
        raise(Slot::NetRx);
    }
    fn noop_handler() {}
    static PROCESS_HITS: AtomicU32 = AtomicU32::new(0);
    fn process_handler() { PROCESS_HITS.fetch_add(1, Ordering::Relaxed); }

    #[test]
    fn raise_then_run_invokes_handler() {
        T_HITS.store(0, Ordering::Relaxed);
        PENDING[0].store(0, Ordering::Relaxed);
        set_handler(Slot::FbconFlush, t_handler);
        raise(Slot::FbconFlush);
        assert!(pending());
        // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
        unsafe { run_pending(); }
        assert!(!pending());
        assert_eq!(T_HITS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn process_only_slot_waits_for_process_drain() {
        PROCESS_HITS.store(0, Ordering::Relaxed);
        PENDING[0].store(0, Ordering::Relaxed);
        PROCESS_PENDING.store(0, Ordering::Relaxed);
        set_handler(Slot::NetNsReap, process_handler);
        raise_process(Slot::NetNsReap);
        // SAFETY: hosted test models an IRQ-tail accounting bracket.
        unsafe { run_pending(); }
        assert_eq!(PROCESS_HITS.load(Ordering::Relaxed), 0);
        assert!(pending());
        // SAFETY: hosted test models the ksoftirqd accounting bracket.
        unsafe { run_pending_process(); }
        assert_eq!(PROCESS_HITS.load(Ordering::Relaxed), 1);
        assert!(!pending());
    }

    #[test]
    fn run_pending_drains_until_empty() {
        T_HITS.store(0, Ordering::Relaxed);
        PENDING[0].store(0, Ordering::Relaxed);
        set_handler(Slot::FbconFlush, t_handler);
        raise(Slot::FbconFlush);
        raise(Slot::FbconFlush);
        // Even multiple raises before run collapse to one bit; one call.
        // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
        unsafe { run_pending(); }
        assert_eq!(T_HITS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unset_slot_no_handler_no_call() {
        PENDING[0].store(0, Ordering::Relaxed);
        HANDLERS[Slot::InputDrain as usize].store(core::ptr::null_mut(), Ordering::Relaxed);
        raise(Slot::InputDrain);
        // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
        unsafe { run_pending(); }
        // No panic, no crash; just a no-op.
        assert!(!pending());
    }

    #[test]
    fn clear_handler_removes_handler_and_pending_bit() {
        T_HITS.store(0, Ordering::Relaxed);
        PENDING[0].store(0, Ordering::Relaxed);
        set_handler(Slot::VsockRx, t_handler);
        raise(Slot::VsockRx);
        assert!(pending());
        let old = clear_handler(Slot::VsockRx);
        assert!(!old.is_null());
        assert!(!pending());
        // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
        unsafe { run_pending(); }
        assert_eq!(T_HITS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn self_rearming_handler_is_bounded() {
        REARM_HITS.store(0, Ordering::Relaxed);
        PENDING[0].store(0, Ordering::Relaxed);
        set_handler(Slot::NetRx, rearming_handler);
        raise(Slot::NetRx);
        // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
        unsafe { run_pending(); }
        // Capped at MAX_SOFTIRQ_RESTART passes — NOT an infinite livelock.
        assert_eq!(REARM_HITS.load(Ordering::Relaxed), MAX_SOFTIRQ_RESTART);
        // Still-pending work is deferred (left set), not dropped.
        assert!(pending());
        // Reset shared statics so sibling tests aren't tainted.
        set_handler(Slot::NetRx, noop_handler);
        PENDING[0].store(0, Ordering::Relaxed);
    }
}
