// Device poll list. One NET_RX softirq slot serves every RX source, so an
// interrupt-driven driver registers its poll routine here instead of claiming
// the slot for itself — two drivers claiming one slot would leave whichever
// probed last as the only RX path in the system.
//
// `fn()` pointers, not trait objects: `07§5` forbids `dyn` in the kernel, and
// the indirection is also what keeps the driver's receive subtree off the
// caller's static call graph.

use core::sync::atomic::{AtomicPtr, Ordering};

use super::limits::NAPI_POLL_SLOTS;

static POLLS: [AtomicPtr<()>; NAPI_POLL_SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; NAPI_POLL_SLOTS];

/// Add a driver poll routine to the list. Idempotent: registering the same
/// routine twice occupies one slot. Returns false when the list is full — the
/// caller's device then has no bottom half and must fail its probe rather than
/// run with silently dropped RX.
/// # C: O(NAPI_POLL_SLOTS)
pub fn register_poll(f: fn()) -> bool {
    super::action::install();
    let raw = f as *mut ();
    for slot in POLLS.iter() {
        if slot.load(Ordering::Acquire) == raw { return true; }
    }
    for slot in POLLS.iter() {
        if slot.compare_exchange(core::ptr::null_mut(), raw,
                                 Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return true;
        }
    }
    false
}

/// Remove a driver poll routine. No-op when absent. # C: O(NAPI_POLL_SLOTS)
pub fn unregister_poll(f: fn()) {
    let raw = f as *mut ();
    for slot in POLLS.iter() {
        let _ = slot.compare_exchange(raw, core::ptr::null_mut(),
                                      Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Run every registered poll routine once. # C: O(NAPI_POLL_SLOTS + polled work)
/// # Ctx: NET_RX bottom half
pub fn poll_all() {
    for slot in POLLS.iter() {
        let raw = slot.load(Ordering::Acquire);
        if raw.is_null() { continue; }
        // SAFETY: raw was stored by register_poll from a live `fn()` value and is cleared before that routine's owner goes away; the reverse cast restores the identical ABI.
        let f: fn() = unsafe { core::mem::transmute::<*mut (), fn()>(raw) };
        f();
    }
}

/// Registered poll routines. # C: O(NAPI_POLL_SLOTS)
pub fn registered() -> usize {
    POLLS.iter().filter(|s| !s.load(Ordering::Acquire).is_null()).count()
}
