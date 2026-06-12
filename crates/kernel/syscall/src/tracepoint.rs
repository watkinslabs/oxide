// Syscall-entry/exit tracepoint hooks (Linux `trace_sys_enter`/`sys_exit`).
// Lives in the low-level `syscall` crate so the dispatch path (`syscalls`
// crate) can fire them and `tracefs` can install them — neither depends on
// the other. Installing a hook IS enabling the event; the dispatch hot path
// pays one atomic load + null check per syscall while the event is off.

use core::sync::atomic::{AtomicPtr, Ordering};

/// `sys_enter` hook: receives the syscall nr. # type
pub type SysEnterFn = fn(u32);
/// `sys_exit` hook: receives the syscall nr + the return value. # type
pub type SysExitFn = fn(u32, i64);

static SYS_ENTER_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static SYS_EXIT_HOOK:  AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install (Some) / clear (None) the sys_enter hook. # C: O(1)
pub fn install_sys_enter_hook(f: Option<SysEnterFn>) {
    SYS_ENTER_HOOK.store(f.map(|p| p as *mut ()).unwrap_or(core::ptr::null_mut()), Ordering::Release);
}
/// Install (Some) / clear (None) the sys_exit hook. # C: O(1)
pub fn install_sys_exit_hook(f: Option<SysExitFn>) {
    SYS_EXIT_HOOK.store(f.map(|p| p as *mut ()).unwrap_or(core::ptr::null_mut()), Ordering::Release);
}

/// Fire the sys_enter hook if installed. # C: O(1) when off
#[inline]
pub fn fire_sys_enter(nr: u32) {
    let raw = SYS_ENTER_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: raw was installed via `install_sys_enter_hook` with the
    // documented `fn(u32)` signature; non-null implies a live fn pointer.
    let f: SysEnterFn = unsafe { core::mem::transmute(raw) };
    f(nr);
}

/// Fire the sys_exit hook if installed. # C: O(1) when off
#[inline]
pub fn fire_sys_exit(nr: u32, ret: i64) {
    let raw = SYS_EXIT_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: raw was installed via `install_sys_exit_hook` with the
    // documented `fn(u32, i64)` signature; non-null implies a live fn pointer.
    let f: SysExitFn = unsafe { core::mem::transmute(raw) };
    f(nr, ret);
}
