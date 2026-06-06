// Boot-installed hooks for kernel-global state procfs reports but doesn't own
// (keeps procfs a leaf crate — kernel installs these at boot, docs/53).
use core::sync::atomic::{AtomicPtr, Ordering};
use alloc::vec::Vec;

static BOOT_SECS: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static HOST_GET:  AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static HOST_SET:  AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static CMDLINE:   AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1)
pub fn set_boot_unix_secs_hook(f: fn() -> u64) { BOOT_SECS.store(f as *mut (), Ordering::Release); }
/// # C: O(1)
pub fn set_hostname_hooks(get: fn() -> Vec<u8>, set: fn(&[u8])) {
    HOST_GET.store(get as *mut (), Ordering::Release);
    HOST_SET.store(set as *mut (), Ordering::Release);
}
/// # C: O(1)
pub fn set_cmdline_hook(f: fn() -> &'static [u8]) { CMDLINE.store(f as *mut (), Ordering::Release); }

/// # C: O(1)
pub fn boot_unix_seconds() -> u64 {
    let p = BOOT_SECS.load(Ordering::Acquire);
    if p.is_null() { return 0; }
    // SAFETY: pointer was set from a `fn() -> u64` via set_boot_unix_secs_hook.
    let f: fn() -> u64 = unsafe { core::mem::transmute(p) }; f()
}
/// # C: O(1)
pub fn hostname() -> Vec<u8> {
    let p = HOST_GET.load(Ordering::Acquire);
    if p.is_null() { return Vec::new(); }
    // SAFETY: pointer set from a `fn() -> Vec<u8>` via set_hostname_hooks.
    let f: fn() -> Vec<u8> = unsafe { core::mem::transmute(p) }; f()
}
/// # C: O(1)
pub fn set_hostname(b: &[u8]) {
    let p = HOST_SET.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: pointer set from a `fn(&[u8])` via set_hostname_hooks.
    let f: fn(&[u8]) = unsafe { core::mem::transmute(p) }; f(b)
}
/// # C: O(1)
pub fn cmdline() -> &'static [u8] {
    let p = CMDLINE.load(Ordering::Acquire);
    if p.is_null() { return b""; }
    // SAFETY: pointer set from a `fn() -> &'static [u8]` via set_cmdline_hook.
    let f: fn() -> &'static [u8] = unsafe { core::mem::transmute(p) }; f()
}
