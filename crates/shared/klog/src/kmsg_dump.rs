// `kmsg_dump` — the call the kernel makes, on its way to stopping, to let a
// registered dumper snapshot the log ring.
//
// It lives here, with the ring, because the ring is what a dumper reads: a
// copy of this hook next to any one caller would leave every other stopping
// path silently un-dumped. The callers are the panic handler and the
// machine-restart path, matching where the reference calls it.
//
// One dumper, installed once at boot, held as a plain `fn` pointer: the
// caller may be a failing kernel, so this path allocates nothing, takes no
// lock, and never waits.

use core::sync::atomic::{AtomicPtr, Ordering};

/// A dumper: called with the raw reason code. The reason's meaning belongs to
/// the dumper, which is the party that filters on it.
pub type DumpFn = fn(u8);

/// `KMSG_DUMP_PANIC` — the kernel has stopped and will not continue.
pub const REASON_PANIC: u8 = 1;
/// `KMSG_DUMP_OOPS` — a fault the kernel survived.
pub const REASON_OOPS: u8 = 2;
/// `KMSG_DUMP_EMERG` — an emergency restart, skipping orderly shutdown.
pub const REASON_EMERG: u8 = 3;
/// `KMSG_DUMP_SHUTDOWN` — an orderly restart or power-off.
pub const REASON_SHUTDOWN: u8 = 4;

static DUMP_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the dumper (`kmsg_dump_register`). # C: O(1)
pub fn set_kmsg_dump_hook(f: DumpFn) {
    DUMP_FN.store(f as *mut (), Ordering::Release);
}

/// Detach the dumper (`kmsg_dump_unregister`). # C: O(1)
pub fn clear_kmsg_dump_hook() {
    DUMP_FN.store(core::ptr::null_mut(), Ordering::Release);
}

/// Notify the registered dumper that the kernel is stopping for `reason`.
/// A no-op when nothing is registered, which is the state for most of boot.
/// # C: O(1) plus the dumper's own cost
/// # Ctx: any, including a panicking kernel with locks held
pub fn kmsg_dump(reason: u8) {
    let raw = DUMP_FN.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: DUMP_FN is only ever populated by `set_kmsg_dump_hook`, which
    // casts a valid `DumpFn` through `as *mut ()`; the reverse cast restores
    // the identical signature, and `DumpFn` carries no unsafe contract.
    let f: DumpFn = unsafe { core::mem::transmute::<*mut (), DumpFn>(raw) };
    f(reason);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering as O};
    use std::sync::Mutex;

    static SERIAL: Mutex<()> = Mutex::new(());
    static SEEN: AtomicU32 = AtomicU32::new(0);

    fn record(reason: u8) { SEEN.store(reason as u32, O::Relaxed); }

    #[test]
    fn a_dump_before_registration_is_a_noop() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_kmsg_dump_hook();
        kmsg_dump(REASON_PANIC);
    }

    #[test]
    fn the_registered_dumper_receives_the_reason() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        SEEN.store(0, O::Relaxed);
        set_kmsg_dump_hook(record);
        kmsg_dump(REASON_SHUTDOWN);
        assert_eq!(SEEN.load(O::Relaxed), REASON_SHUTDOWN as u32);
        clear_kmsg_dump_hook();
        kmsg_dump(REASON_PANIC);
        assert_eq!(SEEN.load(O::Relaxed), REASON_SHUTDOWN as u32, "cleared hook must not fire");
    }
}
