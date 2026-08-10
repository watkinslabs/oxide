// Booting the staged crash image from the panic path.
//
// The panicking CPU may already hold anything, so nothing here waits: a step
// that cannot be taken is skipped and the panic falls through to whatever it
// would have done without a crash image. A crash boot that deadlocked would
// convert a reported panic into a silent hang, which is strictly worse than
// no crash boot at all.

use core::sync::atomic::{AtomicPtr, Ordering};

/// Takes the staged crash image past the point of no return. Returns only on
/// failure — the image is entered, the other CPUs are stopped and interrupts
/// are masked on the way in.
pub type CrashBootFn = fn() -> bool;

static CRASH_BOOT: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the crash-boot entry point. # C: O(1)
pub fn set_crash_boot_hook(f: CrashBootFn) { CRASH_BOOT.store(f as *mut (), Ordering::Release); }

/// The installed crash-boot entry point, if any. # C: O(1)
pub fn crash_boot_hook() -> Option<CrashBootFn> {
    let raw = CRASH_BOOT.load(Ordering::Acquire);
    if raw.is_null() { return None; }
    // SAFETY: CRASH_BOOT is written only by set_crash_boot_hook, which casts a valid CrashBootFn pointer into the slot; the reverse cast restores the identical signature and CrashBootFn carries no unsafe contract.
    Some(unsafe { core::mem::transmute::<*mut (), CrashBootFn>(raw) })
}

/// Is a crash boot worth attempting at all?
///
/// Global-free so the panic path's one branch is decided in a hosted test.
/// Every "no" here has to fall through to the ordinary panic handling rather
/// than stopping the CPU: a machine with no crash image loaded must still
/// print, still snapshot, and still honour the boot line's restart request.
///
/// Neither input is allowed to be a lock acquisition. The panicking CPU may
/// hold the very lock that guards the image slots, and a blocking read here
/// turns a reported panic into a silent hang — the answer is read from the
/// published reservation, and the slot itself is only ever consulted behind
/// the try-lock inside the installed entry point.
/// # C: O(1)
pub fn crash_boot_wanted(hook_installed: bool, region_reserved: bool) -> bool {
    hook_installed && region_reserved
}

/// The panic path's crash-boot attempt. Never returns on success.
///
/// Returns on every other path — no image, no region, no entry point, or a
/// contended lock — leaving the caller to carry on with the panic it was
/// already reporting.
/// # C: O(image size)
pub fn crash_kexec() {
    let hook = crash_boot_hook();
    if !crash_boot_wanted(hook.is_some(), crate::crashk::crash_size() != 0) { return; }
    if let Some(f) = hook { f(); }
}
