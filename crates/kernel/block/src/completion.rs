//! Shared block-completion bottom half.
//!
//! Device hard handlers only acknowledge hardware and call [`raise`]. The
//! `BlockIo` softirq fans out to every registered block driver so completion
//! parsing, allocation, and task wakeup stay outside hard-IRQ context.

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use sync::{Spinlock, TaskList as CompletionRegistrationClass};

const MAX_COMPLETION_HANDLERS: usize = 8;

static HANDLERS: [AtomicPtr<()>; MAX_COMPLETION_HANDLERS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_COMPLETION_HANDLERS];
static REGISTRATION: Spinlock<(), CompletionRegistrationClass> = Spinlock::new(());
static DISPATCH_INSTALLED: AtomicBool = AtomicBool::new(false);

fn dispatch() {
    for handler in &HANDLERS {
        let raw = handler.load(Ordering::Acquire);
        if raw.is_null() { continue; }
        // SAFETY: register stores only pointers cast from the exact fn() ABI.
        let f: fn() = unsafe { core::mem::transmute(raw) };
        f();
    }
}

fn ensure_dispatch_installed() {
    if DISPATCH_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let previous = softirq::set_handler(softirq::Slot::BlockIo, dispatch);
        debug_assert!(previous.is_null() || previous == dispatch as *mut ());
    }
}

/// Register one driver's process-safe completion bottom half.
///
/// Re-registering the same function is idempotent. Returns false only when the
/// fixed handler table is full.
/// # C: O(N_drivers)
/// # Ctx: process/boot context
pub fn register(handler: fn()) -> bool {
    let raw = handler as *mut ();
    let _registration = REGISTRATION.lock();
    if HANDLERS.iter().any(|slot| slot.load(Ordering::Acquire) == raw) {
        return true;
    }
    let Some(slot) = HANDLERS
        .iter()
        .find(|slot| slot.load(Ordering::Acquire).is_null())
    else {
        return false;
    };
    slot.store(raw, Ordering::Release);
    ensure_dispatch_installed();
    true
}

/// Remove a previously registered completion bottom half.
/// # C: O(N_drivers)
/// # Ctx: process/boot context
pub fn unregister(handler: fn()) -> bool {
    let raw = handler as *mut ();
    let _registration = REGISTRATION.lock();
    let Some(slot) = HANDLERS
        .iter()
        .find(|slot| slot.load(Ordering::Acquire) == raw)
    else {
        return false;
    };
    slot.store(core::ptr::null_mut(), Ordering::Release);
    true
}

/// Raise the shared block-completion softirq on the current CPU.
/// # C: O(1)
/// # Ctx: hard IRQ or pinned process context
pub fn raise() {
    softirq::raise(softirq::Slot::BlockIo);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    static FIRST: AtomicU32 = AtomicU32::new(0);
    static SECOND: AtomicU32 = AtomicU32::new(0);

    fn first() { FIRST.fetch_add(1, Ordering::Relaxed); }
    fn second() { SECOND.fetch_add(1, Ordering::Relaxed); }

    #[test]
    fn dispatch_fans_out_and_registration_is_idempotent() {
        assert!(register(first));
        assert!(register(first));
        assert!(register(second));
        dispatch();
        assert_eq!(FIRST.load(Ordering::Relaxed), 1);
        assert_eq!(SECOND.load(Ordering::Relaxed), 1);
        assert!(unregister(first));
        dispatch();
        assert_eq!(FIRST.load(Ordering::Relaxed), 1);
        assert_eq!(SECOND.load(Ordering::Relaxed), 2);
        assert!(unregister(second));
        assert!(!unregister(second));
    }
}
