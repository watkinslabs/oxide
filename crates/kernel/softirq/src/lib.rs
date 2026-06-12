// Softirq primitive per docs/45 (DRAFT). Linux-equivalent bottom-half
// runner: ISR / process context calls `raise(slot)` to mark a deferred
// handler pending; `run_pending()` is invoked from the timer-ISR tail
// (after EOI, with IRQs unmasked) and walks the bitmask, calling each
// installed handler. Slots are statically numbered (`Slot::*`) so the
// dispatch is a fixed-size table — no allocation, no dyn, no lock.
//
// Concurrency
//   - PENDING is a u32 AtomicU32. `raise` is fetch_or; `run_pending`
//     atomically swaps to 0 and drains. Multiple raises during a
//     handler simply re-flag — the runner loops until PENDING is 0.
//   - IN_PROGRESS guards against re-entry: a nested timer ISR that
//     calls run_pending observes IN_PROGRESS=true and returns; the
//     outer runner drains the new pending bits on its next iteration.
//   - Handlers run with IRQs enabled by the timer-ISR shim; nested
//     timer IRQs can fire but their `run_pending` calls bail on
//     IN_PROGRESS so we never recurse.
//
// Limits
//   - 32 slots (one u32 of pending bits). Bump to u64 + 64 handlers
//     if we exhaust them.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

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
}

const N_SLOTS: usize = 32;

/// Pending bitmask. Bit `Slot::* as u32` set ⇒ handler must run.
static PENDING: AtomicU32 = AtomicU32::new(0);

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

/// Re-entry guard. Set while `run_pending` is draining; nested
/// callers (from a timer that fires inside a handler) observe true
/// and bail. The outer drain loop picks up their pending bits.
static IN_PROGRESS: AtomicBool = AtomicBool::new(false);

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

/// Install the `need_resched()` peek (non-consuming). # C: O(1)
pub fn set_resched_hook(f: fn() -> bool) { RESCHED_HOOK.store(f as *mut (), Ordering::Release); }
/// Install the jiffies/tick reader. # C: O(1)
pub fn set_jiffies_hook(f: fn() -> u64) { JIFFIES_HOOK.store(f as *mut (), Ordering::Release); }
/// Install `wakeup_softirqd` — the deferral target run when the restart gate
/// trips with work still pending. # C: O(1)
pub fn set_wakeup_hook(f: fn()) { WAKEUP_HOOK.store(f as *mut (), Ordering::Release); }

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

/// Mark `slot` as needing a deferred-handler run. Cheap fetch_or;
/// safe to call from any context (ISR, process, softirq itself).
/// # C: O(1) — atomic fetch_or.
pub fn raise(slot: Slot) {
    PENDING.fetch_or(1u32 << (slot as u32), Ordering::Release);
    RAISES.fetch_add(1, Ordering::Relaxed);
}

/// True iff at least one slot is pending. Cheap acquire load.
/// # C: O(1)
pub fn pending() -> bool { PENDING.load(Ordering::Acquire) != 0 }

/// Drain the pending bitmask, calling each set slot's handler.
/// Loops until PENDING is 0 (so a handler that raises another bit
/// is observed in the same drain).
///
/// # Ctx
/// Must run with IRQs enabled — handlers may wait on device IRQ
/// acks (virtio used-idx). Caller (the ISR shim) is responsible
/// for the `sti` / `cli` envelope.
///
/// # SAFETY
/// Caller must have enabled IRQs locally before calling. Re-entry
/// is guarded by `IN_PROGRESS`; nested calls return without doing
/// work, and the outer drain picks up new bits.
///
/// # C: O(N_handlers_with_work) per drain pass; bounded by handler
/// runtime + the number of times handlers re-raise themselves.
pub unsafe fn run_pending() {
    if IN_PROGRESS
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    RUNS.fetch_add(1, Ordering::Relaxed);
    // Linux `__do_softirq` restart gate. A handler that re-raises its own bit
    // (NetRx re-armed by each RX MSI under a packet flood) would otherwise
    // spin this loop forever: the CPU never returns to the timer-ISR tail, the
    // percpu heartbeat goes unstamped, and the hard-lockup watchdog fires.
    // Mirror the kernel exactly — after running the pending set, restart only
    // while `time_before(jiffies, end) && !need_resched() && --max_restart`;
    // otherwise `wakeup_softirqd()` and return, leaving still-pending bits set
    // for the deferral target to finish.
    let end = jiffies().wrapping_add(MAX_SOFTIRQ_TIME);
    let mut max_restart = MAX_SOFTIRQ_RESTART;
    loop {
        // `set_softirq_pending(0)` — claim the current set, run each handler.
        let bits = PENDING.swap(0, Ordering::AcqRel);
        if bits == 0 {
            break;
        }
        let mut b = bits;
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
        // Re-raised during the pass? Apply the three-way restart gate.
        if !pending() {
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
        // Gate tripped with work pending → hand off to the deferral target
        // (Linux wakes per-CPU ksoftirqd; oxide's installed hook re-arms a
        // prompt drain). The still-pending bits remain set in PENDING.
        wakeup_softirqd();
        DEFERRALS.fetch_add(1, Ordering::Relaxed);
        break;
    }
    IN_PROGRESS.store(false, Ordering::Release);
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

    #[test]
    fn raise_then_run_invokes_handler() {
        T_HITS.store(0, Ordering::Relaxed);
        PENDING.store(0, Ordering::Relaxed);
        set_handler(Slot::FbconFlush, t_handler);
        raise(Slot::FbconFlush);
        assert!(pending());
        // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
        unsafe { run_pending(); }
        assert!(!pending());
        assert_eq!(T_HITS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn run_pending_drains_until_empty() {
        T_HITS.store(0, Ordering::Relaxed);
        PENDING.store(0, Ordering::Relaxed);
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
        PENDING.store(0, Ordering::Relaxed);
        HANDLERS[Slot::InputDrain as usize].store(core::ptr::null_mut(), Ordering::Relaxed);
        raise(Slot::InputDrain);
        // SAFETY: hosted unit test; no IRQs to coordinate with; sole caller of run_pending in this thread.
        unsafe { run_pending(); }
        // No panic, no crash; just a no-op.
        assert!(!pending());
    }

    #[test]
    fn self_rearming_handler_is_bounded() {
        REARM_HITS.store(0, Ordering::Relaxed);
        PENDING.store(0, Ordering::Relaxed);
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
        PENDING.store(0, Ordering::Relaxed);
    }
}
