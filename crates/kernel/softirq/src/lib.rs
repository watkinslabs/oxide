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

/// Diagnostic counters.
pub static RAISES: AtomicU32 = AtomicU32::new(0);
pub static RUNS: AtomicU32 = AtomicU32::new(0);
pub static HANDLER_CALLS: AtomicU32 = AtomicU32::new(0);

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
    loop {
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
    }
    IN_PROGRESS.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    static T_HITS: AtomicU32 = AtomicU32::new(0);
    fn t_handler() { T_HITS.fetch_add(1, Ordering::Relaxed); }

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
}
