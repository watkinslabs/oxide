// The kernel-wide PC-beep handoff. VT owns the ioctl ABI; the sound driver
// that owns a beep generator supplies the hardware operation here.

use core::sync::atomic::{AtomicPtr, Ordering};

static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the current sound device's PC-beep owner. # C: O(1)
pub fn set_hook(f: fn(u32, u32) -> bool) { HOOK.store(f as *mut (), Ordering::Release); }

/// Generate or stop a tone. `milliseconds == 0` means continuous playback.
/// # C: O(1) plus backend
pub fn beep(hz: u32, milliseconds: u32) -> bool {
    let raw = HOOK.load(Ordering::Acquire);
    if raw.is_null() { return false; }
    // SAFETY: only `set_hook` stores this pointer, from the exact function ABI.
    let f: fn(u32, u32) -> bool = unsafe { core::mem::transmute(raw) };
    f(hz, milliseconds)
}
