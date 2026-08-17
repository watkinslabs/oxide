// Lifetime of an external io_uring command whose address is handed to a
// loadable-module driver as a bare pointer (`30`, `53`).
//
// Ownership rule, as the reference states it for `io_uring_cmd`: the command
// is not a driver allocation. It is the ring's request, and the ring holds it
// until the one terminal completion a driver owes after it answered
// `-EIOCBQUEUED`. Nothing in the completion hook frees storage; the hook
// records the result and hands the request back to the ring, which frees it
// after the CQE is posted. A task-work hand-off likewise takes no reference of
// its own: upstream the callback and the completion are the same per-request
// task-work node run on one task, so they cannot overlap.
//
// This kernel queues the hand-off on a workqueue, which CAN overlap a driver
// completion arriving on another CPU, so the reference upstream gets for free
// has to be taken explicitly. That is what this module owns: every hand-off
// carries a strong reference, and exactly one caller wins the terminal
// completion and consumes the driver's reference.
//
// Precondition on the caller (identical to upstream, and not enforceable from
// a bare pointer): a driver keeps the command alive for the duration of any
// core hook it calls, completes it at most once, and touches it never after
// completing it. `claim_done` is defence against a driver that breaks the
// second half — it stops a second CQE and a second release — not a lifetime
// guarantee, because reading the flag is itself a dereference.

use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Terminal-completion and task-hand-off claims of one external command.
pub struct CmdClaims { done: AtomicBool, task: AtomicUsize }

impl Default for CmdClaims { fn default() -> Self { Self::new() } }

impl CmdClaims {
    /// # C: O(1)
    pub const fn new() -> Self { Self { done: AtomicBool::new(false), task: AtomicUsize::new(0) } }

    /// True exactly once, for the caller that owns the terminal completion.
    /// # C: O(1)
    pub fn claim_done(&self) -> bool { !self.done.swap(true, Ordering::AcqRel) }

    /// Arm one pending task callback; false while a callback is already armed.
    /// # C: O(1)
    pub fn arm(&self, callback: usize) -> bool {
        callback != 0 && self.task.compare_exchange(0, callback, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Take the armed callback, freeing the slot for a later hand-off.
    /// # C: O(1)
    pub fn take(&self) -> usize { self.task.swap(0, Ordering::AcqRel) }
}

/// A command whose storage is reference-counted and whose claims live in it.
pub trait CmdLifetime { fn claims(&self) -> &CmdClaims; }

/// Borrow the reference the driver holds, without consuming it.
///
/// # Safety
/// `raw` came from `Arc::into_raw` on a command whose driver reference the
/// caller has not released and cannot release for the duration of the borrow.
/// # C: O(1)
unsafe fn borrow<T: CmdLifetime>(raw: *const T) -> ManuallyDrop<Arc<T>> {
    // SAFETY: the caller's precondition names raw as a live Arc::into_raw
    // pointer; ManuallyDrop keeps the reconstructed handle from releasing the
    // reference it did not take.
    ManuallyDrop::new(unsafe { Arc::from_raw(raw) })
}

/// Arm a task callback and take the reference the worker will run under.
/// `Some(raw)` is a strong reference the hand-off owns until `take_handoff`.
///
/// # Safety
/// As `borrow`: `raw` names a live command the caller is keeping alive across
/// this call.
/// # C: O(1)
pub unsafe fn arm_handoff<T: CmdLifetime>(raw: *const T, callback: usize) -> Option<*const T> {
    if raw.is_null() { return None; }
    // SAFETY: raw is the live command named by this function's own contract.
    let owner = unsafe { borrow(raw) };
    if !owner.claims().arm(callback) { return None; }
    Some(Arc::into_raw(Arc::clone(&owner)))
}

/// Consume the hand-off reference and its armed callback.
/// `None` releases the reference and runs nothing.
///
/// # Safety
/// `raw` is the pointer a matching `arm_handoff` returned, consumed once.
/// # C: O(1)
pub unsafe fn take_handoff<T: CmdLifetime>(raw: *const T) -> Option<(Arc<T>, usize)> {
    if raw.is_null() { return None; }
    // SAFETY: the caller passes the hand-off reference arm_handoff created, so
    // reclaiming it here balances that one Arc::into_raw exactly once.
    let owned = unsafe { Arc::from_raw(raw) };
    let task = owned.claims().take();
    if task == 0 { return None; }
    Some((owned, task))
}

/// Claim the single terminal completion, taking the driver's reference with it.
/// `None` means another caller already completed; it consumes nothing.
///
/// # Safety
/// As `borrow`: `raw` names a command the calling driver has kept alive for
/// this call and will not complete again.
/// # C: O(1)
pub unsafe fn claim_terminal<T: CmdLifetime>(raw: *const T) -> Option<Arc<T>> {
    if raw.is_null() { return None; }
    // SAFETY: raw is the live command named by this function's own contract.
    let owner = unsafe { borrow(raw) };
    if !owner.claims().claim_done() { return None; }
    Some(ManuallyDrop::into_inner(owner))
}

#[cfg(test)]
mod tests;
