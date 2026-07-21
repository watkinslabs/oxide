// printk `struct console` registry (Linux `kernel/printk/printk.c`
// `register_console` / `console_unlock` fan-out). A small fixed array of
// registered console sinks; printk fans every byte-run to the dmesg ring
// then to each registered console. NO `dyn`, NO alloc — klog is
// `#![no_std]` and runs pre-alloc / in early boot, so the registry is a
// static array of `fn(&[u8])` pointers + flags guarded by atomics.
//
// `set_byte_sink` / `set_aux_sink` (lib.rs) are thin shims that occupy two
// reserved slots (BYTE = the serial console, AUX = the fbcon console), so
// the historical ordering ring → serial → fbcon is preserved bit-for-bit
// and pre-registration emits are safe no-ops.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// A console sink: called with each emitted byte-run (prefix, message,
/// newline, raw bytes). Plain `fn` pointer — no `dyn` (`07§5`).
pub type ConsoleSink = fn(&[u8]);

/// Registry capacity. Two slots are reserved (`SLOT_BYTE`, `SLOT_AUX`) for
/// the `set_byte_sink` / `set_aux_sink` shims; the rest are general
/// `register_console` slots. Sized for the kernel's console count
/// (serial + fbcon VT + headroom for netconsole / extra UARTs).
pub const MAX_CONSOLES: usize = 8;

/// Reserved slot index for the primary byte sink (serial console).
pub const SLOT_BYTE: usize = 0;
/// Reserved slot index for the aux sink (fbcon VT console).
pub const SLOT_AUX: usize = 1;
/// First general-purpose `register_console` slot.
pub const SLOT_GENERAL: usize = 2;

/// `CON_ENABLED`: slot holds a live sink and receives emits.
pub const CON_ENABLED: u32 = 0x1;

struct ConsoleSlot {
    sink: AtomicPtr<()>,
    flags: AtomicU32,
}

impl ConsoleSlot {
    const fn empty() -> Self {
        ConsoleSlot {
            sink: AtomicPtr::new(core::ptr::null_mut()),
            flags: AtomicU32::new(0),
        }
    }
}

struct Registry {
    slots: [ConsoleSlot; MAX_CONSOLES],
}

// SAFETY: every Registry field is an atomic (AtomicPtr / AtomicU32); all
// reads/writes use Acquire/Release ordering and the array is fixed-size,
// so concurrent register/emit from any CPU is data-race-free without a
// lock. No interior non-atomic state exists.
unsafe impl Sync for Registry {}

static REGISTRY: Registry = Registry {
    slots: [
        ConsoleSlot::empty(),
        ConsoleSlot::empty(),
        ConsoleSlot::empty(),
        ConsoleSlot::empty(),
        ConsoleSlot::empty(),
        ConsoleSlot::empty(),
        ConsoleSlot::empty(),
        ConsoleSlot::empty(),
    ],
};

/// Install (or replace) the sink in reserved slot `idx`. Internal helper
/// for the `set_byte_sink` / `set_aux_sink` shims.
/// # C: O(1)
pub(crate) fn install_slot(idx: usize, f: ConsoleSink) {
    if idx >= MAX_CONSOLES {
        return;
    }
    let slot = &REGISTRY.slots[idx];
    slot.sink.store(f as *mut (), Ordering::Release);
    slot.flags.store(CON_ENABLED, Ordering::Release);
}

/// Detach the sink in reserved slot `idx` (subsequent emits skip it).
/// # C: O(1)
pub(crate) fn clear_slot(idx: usize) {
    if idx >= MAX_CONSOLES {
        return;
    }
    let slot = &REGISTRY.slots[idx];
    slot.flags.store(0, Ordering::Release);
    slot.sink.store(core::ptr::null_mut(), Ordering::Release);
}

/// Register `f` as a printk console (Linux `register_console`). Occupies
/// the first free general slot; subsequent printk byte-runs fan out to it.
/// Returns the slot index, or `None` if the registry is full. Idempotent
/// for an already-registered sink (returns its existing slot).
/// # C: O(MAX_CONSOLES)
pub fn register_console(f: ConsoleSink) -> Option<usize> {
    let target = f as *mut ();
    // Already registered? Return existing slot (idempotent).
    let mut i = SLOT_GENERAL;
    while i < MAX_CONSOLES {
        let slot = &REGISTRY.slots[i];
        if slot.flags.load(Ordering::Acquire) & CON_ENABLED != 0
            && slot.sink.load(Ordering::Acquire) == target
        {
            return Some(i);
        }
        i += 1;
    }
    // Claim the first free slot.
    let mut i = SLOT_GENERAL;
    while i < MAX_CONSOLES {
        let slot = &REGISTRY.slots[i];
        if slot.flags.load(Ordering::Acquire) & CON_ENABLED == 0 {
            slot.sink.store(target, Ordering::Release);
            slot.flags.store(CON_ENABLED, Ordering::Release);
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Unregister the console `f` (Linux `unregister_console`). Clears every
/// general slot whose sink matches `f`. Reserved slots are untouched (use
/// the `clear_*_sink` shims). # C: O(MAX_CONSOLES)
pub fn unregister_console(f: ConsoleSink) {
    let target = f as *mut ();
    let mut i = SLOT_GENERAL;
    while i < MAX_CONSOLES {
        let slot = &REGISTRY.slots[i];
        if slot.sink.load(Ordering::Acquire) == target {
            slot.flags.store(0, Ordering::Release);
            slot.sink.store(core::ptr::null_mut(), Ordering::Release);
        }
        i += 1;
    }
}

/// Fan `bytes` to every registered console (Linux `console_unlock` loop).
/// Reserved slots fire first (BYTE=serial, then AUX=fbcon) to preserve the
/// historical ordering, then the general slots in index order. A null /
/// disabled slot is skipped — pre-registration emits are no-ops.
/// # C: O(MAX_CONSOLES) sink calls
#[inline]
pub(crate) fn fan_out(bytes: &[u8]) {
    let mut i = 0usize;
    while i < MAX_CONSOLES {
        let slot = &REGISTRY.slots[i];
        if slot.flags.load(Ordering::Acquire) & CON_ENABLED != 0 {
            let raw = slot.sink.load(Ordering::Acquire);
            if !raw.is_null() {
                // SAFETY: a slot is marked CON_ENABLED with a non-null sink only after install_slot / register_console casts a valid ConsoleSink fn-pointer through `as *mut ()`; the reverse cast restores the identical fn signature; ConsoleSink has no unsafe contract beyond &[u8] validity, which holds.
                let f: ConsoleSink = unsafe { core::mem::transmute::<*mut (), ConsoleSink>(raw) };
                f(bytes);
            }
        }
        i += 1;
    }
}

/// Send emergency diagnostics to the primary console only. This deliberately
/// bypasses auxiliary consoles, whose rendering paths may allocate while an
/// allocator or other leaf lock is held.
/// # C: O(bytes.len())
pub(crate) fn primary_only(bytes: &[u8]) {
    let slot = &REGISTRY.slots[SLOT_BYTE];
    if slot.flags.load(Ordering::Acquire) & CON_ENABLED == 0 { return; }
    let raw = slot.sink.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: SLOT_BYTE is installed through set_byte_sink, which stores a
    // valid ConsoleSink function pointer before setting CON_ENABLED.
    let f: ConsoleSink = unsafe { core::mem::transmute::<*mut (), ConsoleSink>(raw) };
    f(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    // Console registry is process-global; serialize the tests.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn reset_all() {
        let mut i = 0usize;
        while i < MAX_CONSOLES {
            clear_slot(i);
            i += 1;
        }
    }

    static C0: AtomicUsize = AtomicUsize::new(0);
    static C1: AtomicUsize = AtomicUsize::new(0);
    static C2: AtomicUsize = AtomicUsize::new(0);
    fn s0(b: &[u8]) { C0.fetch_add(b.len(), Ordering::Relaxed); }
    fn s1(b: &[u8]) { C1.fetch_add(b.len(), Ordering::Relaxed); }
    fn s2(b: &[u8]) { C2.fetch_add(b.len(), Ordering::Relaxed); }

    #[test]
    fn register_n_consoles_all_get_bytes() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        C0.store(0, Ordering::Relaxed);
        C1.store(0, Ordering::Relaxed);
        C2.store(0, Ordering::Relaxed);
        register_console(s0);
        register_console(s1);
        register_console(s2);
        fan_out(b"hello"); // 5 bytes
        assert_eq!(C0.load(Ordering::Relaxed), 5);
        assert_eq!(C1.load(Ordering::Relaxed), 5);
        assert_eq!(C2.load(Ordering::Relaxed), 5);
        reset_all();
    }

    #[test]
    fn unregister_stops_one() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        C0.store(0, Ordering::Relaxed);
        C1.store(0, Ordering::Relaxed);
        register_console(s0);
        register_console(s1);
        unregister_console(s0);
        fan_out(b"abcd"); // 4 bytes
        assert_eq!(C0.load(Ordering::Relaxed), 0, "unregistered must not fire");
        assert_eq!(C1.load(Ordering::Relaxed), 4);
        reset_all();
    }

    #[test]
    fn pre_registration_emit_is_noop() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        // No consoles registered: fan_out must not panic and must do nothing.
        fan_out(b"nothing here");
        reset_all();
    }

    #[test]
    fn register_is_idempotent() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        let a = register_console(s0);
        let b = register_console(s0);
        assert_eq!(a, b, "re-register same sink returns same slot");
        reset_all();
    }

    #[test]
    fn reserved_slots_fire_in_order() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset_all();
        C0.store(0, Ordering::Relaxed);
        install_slot(SLOT_BYTE, s0);
        install_slot(SLOT_AUX, s1);
        C1.store(0, Ordering::Relaxed);
        fan_out(b"xyz"); // 3 bytes
        assert_eq!(C0.load(Ordering::Relaxed), 3);
        assert_eq!(C1.load(Ordering::Relaxed), 3);
        clear_slot(SLOT_BYTE);
        fan_out(b"q"); // 1 byte, only aux now
        assert_eq!(C0.load(Ordering::Relaxed), 3, "cleared byte slot stops");
        assert_eq!(C1.load(Ordering::Relaxed), 4);
        reset_all();
    }
}
