//! DRM modeset WW-style lock acquisition and backoff.

use super::*;

#[cfg(test)]
const DRM_MODESET_LOCK_SIZE: usize = 48;
const DRM_MODESET_LOCK_MUTEX_OFF: usize = 0;
const DRM_MODESET_LOCK_CTX_OFF: usize = 24;
const DRM_MODESET_LOCK_HEAD_OFF: usize = 32;
const DRM_MODESET_ACQUIRE_CTX_SIZE: usize = 64;
const DRM_MODESET_CTX_CONTENDED_OFF: usize = 24;
const DRM_MODESET_CTX_LOCKED_OFF: usize = 40;
const DRM_MODESET_CTX_TRYLOCK_ONLY_OFF: usize = 56;
const DRM_MODESET_CTX_INTERRUPTIBLE_OFF: usize = 57;
const DRM_MODESET_ACQUIRE_INTERRUPTIBLE: u32 = 1;
const LINUX_EBUSY: i32 = 16;
const LINUX_EDEADLK: i32 = 35;
const LINUX_ERESTARTSYS: i32 = 512;

fn init_list(node: *mut u8) {
    // SAFETY: node is a valid ABI list-head location; its links point to itself while empty.
    unsafe { write(node.cast::<*mut u8>(), node); write(node.add(core::mem::size_of::<*mut u8>()).cast::<*mut u8>(), node); }
}
fn list_empty(head: *mut u8) -> bool {
    // SAFETY: head is an initialized ABI list head whose next pointer is readable.
    unsafe { read(head.cast::<*mut u8>()) == head }
}
fn list_add(node: *mut u8, head: *mut u8) {
    // SAFETY: node is detached and head is initialized; link updates publish one held modeset lock.
    unsafe { let next = read(head.cast::<*mut u8>()); write(node.cast::<*mut u8>(), next); write(node.add(8).cast::<*mut u8>(), head); write(next.add(8).cast::<*mut u8>(), node); write(head.cast::<*mut u8>(), node); }
}
fn list_del_init(node: *mut u8) {
    // SAFETY: node is currently linked into exactly one list, so its adjacent links are valid.
    unsafe { let next = read(node.cast::<*mut u8>()); let prev = read(node.add(8).cast::<*mut u8>()); write(prev.cast::<*mut u8>(), next); write(next.add(8).cast::<*mut u8>(), prev); init_list(node); }
}
fn mutex(lock: *mut u8) -> *mut crate::linux_sync::LinuxMutex { lock.wrapping_add(DRM_MODESET_LOCK_MUTEX_OFF).cast() }
fn held_context(lock: *mut u8) -> *mut u8 {
    // SAFETY: context ownership is embedded in the ABI-pinned ww_mutex context slot.
    unsafe { read(lock.add(DRM_MODESET_LOCK_CTX_OFF).cast::<*mut u8>()) }
}
fn set_context(lock: *mut u8, ctx: *mut u8) {
    // SAFETY: caller owns the locked ww mutex before publishing or withdrawing its acquisition context.
    unsafe { write(lock.add(DRM_MODESET_LOCK_CTX_OFF).cast::<*mut u8>(), ctx); }
}
fn record_lock(lock: *mut u8, ctx: *mut u8) {
    if ctx.is_null() { return; }
    let node = lock.wrapping_add(DRM_MODESET_LOCK_HEAD_OFF);
    if list_empty(node) { list_add(node, ctx.wrapping_add(DRM_MODESET_CTX_LOCKED_OFF)); }
}
fn acquire(lock: *mut u8, ctx: *mut u8, slow: bool) -> i32 {
    if lock.is_null() { return -LINUX_EBUSY; }
    if ctx.is_null() { crate::linux_sync::mutex_lock(mutex(lock)); return 0; }
    if held_context(lock) == ctx { return 0; }
    // SAFETY: trylock_only is an ABI-pinned bool in the caller-owned acquire context.
    let try_only = unsafe { read(ctx.add(DRM_MODESET_CTX_TRYLOCK_ONLY_OFF).cast::<bool>()) };
    if try_only {
        if crate::linux_sync::mutex_trylock(mutex(lock)) == 0 { return -LINUX_EBUSY; }
        set_context(lock, ctx); record_lock(lock, ctx); return 0;
    }
    if !slow {
        if crate::linux_sync::mutex_trylock(mutex(lock)) == 0 {
            // SAFETY: record the contended lock before returning the required restart condition.
            unsafe { write(ctx.add(DRM_MODESET_CTX_CONTENDED_OFF).cast::<*mut u8>(), lock); }
            return -LINUX_EDEADLK;
        }
        set_context(lock, ctx); record_lock(lock, ctx); return 0;
    }
    // SAFETY: ctx was null-checked at function entry and interruptible is an
    // ABI-pinned bool inside the same caller-owned acquire context.
    if slow && unsafe { read(ctx.add(DRM_MODESET_CTX_INTERRUPTIBLE_OFF).cast::<bool>()) } {
        if crate::linux_sync::mutex_lock_interruptible(mutex(lock)) != 0 { return -LINUX_ERESTARTSYS; }
    } else { crate::linux_sync::mutex_lock(mutex(lock)); }
    set_context(lock, ctx); record_lock(lock, ctx); 0
}

pub(super) fn export_symbols() {
    for (name, address) in [
        ("drm_modeset_acquire_init", drm_modeset_acquire_init as *const () as usize),
        ("drm_modeset_acquire_fini", drm_modeset_acquire_fini as *const () as usize),
        ("drm_modeset_drop_locks", drm_modeset_drop_locks as *const () as usize),
        ("drm_modeset_backoff", drm_modeset_backoff as *const () as usize),
        ("drm_modeset_lock_init", drm_modeset_lock_init as *const () as usize),
        ("drm_modeset_lock", drm_modeset_lock as *const () as usize),
        ("drm_modeset_lock_single_interruptible", drm_modeset_lock_single_interruptible as *const () as usize),
        ("drm_modeset_unlock", drm_modeset_unlock as *const () as usize),
    ] { crate::symtab::export(name, address, false); }
}

/// Initialize one acquisition context and its held-lock list. # C: O(1)
pub(super) extern "C" fn drm_modeset_acquire_init(ctx: *mut c_void, flags: u32) {
    if ctx.is_null() { return; }
    // SAFETY: ctx names the complete fixed-size external acquisition-context allocation.
    unsafe { core::ptr::write_bytes(ctx.cast::<u8>(), 0, DRM_MODESET_ACQUIRE_CTX_SIZE); write(ctx.cast::<u8>().add(DRM_MODESET_CTX_INTERRUPTIBLE_OFF).cast::<bool>(), flags & DRM_MODESET_ACQUIRE_INTERRUPTIBLE != 0); }
    init_list(ctx.cast::<u8>().wrapping_add(DRM_MODESET_CTX_LOCKED_OFF));
}
/// Finish an empty acquisition context. # C: O(1)
pub(super) extern "C" fn drm_modeset_acquire_fini(_ctx: *mut c_void) {}
/// Drop every lock held by this acquisition context. # C: O(N_locks)
pub(super) extern "C" fn drm_modeset_drop_locks(ctx: *mut c_void) {
    if ctx.is_null() { return; }
    let ctx = ctx.cast::<u8>(); let head = ctx.wrapping_add(DRM_MODESET_CTX_LOCKED_OFF);
    while !list_empty(head) {
        // SAFETY: the first held list node is lock.head, so subtracting its verified offset recovers the lock.
        let lock = unsafe { read(head.cast::<*mut u8>()).sub(DRM_MODESET_LOCK_HEAD_OFF) };
        drm_modeset_unlock(lock.cast());
    }
}
/// Back off, then acquire the contended lock as the first lock in a retry. # C: O(N_locks)
pub(super) extern "C" fn drm_modeset_backoff(ctx: *mut c_void) -> i32 {
    if ctx.is_null() { return -LINUX_EBUSY; }
    let ctx = ctx.cast::<u8>();
    // SAFETY: contended is written only by a failed acquisition of this exact context.
    let lock = unsafe { read(ctx.add(DRM_MODESET_CTX_CONTENDED_OFF).cast::<*mut u8>()) };
    if lock.is_null() { return 0; }
    // SAFETY: clear before dropping locks, so unlock cannot observe stale retry state.
    unsafe { write(ctx.add(DRM_MODESET_CTX_CONTENDED_OFF).cast::<*mut u8>(), core::ptr::null_mut()); }
    drm_modeset_drop_locks(ctx.cast()); acquire(lock, ctx, true)
}
/// Initialize one modeset lock and its detached list node. # C: O(1)
pub(super) extern "C" fn drm_modeset_lock_init(lock: *mut c_void) {
    if lock.is_null() { return; }
    let lock = lock.cast::<u8>(); crate::linux_sync::mutex_init(mutex(lock)); set_context(lock, core::ptr::null_mut()); init_list(lock.wrapping_add(DRM_MODESET_LOCK_HEAD_OFF));
}
/// Acquire one modeset resource and track it in an optional retry context. # C: O(1) uncontended
pub(super) extern "C" fn drm_modeset_lock(lock: *mut c_void, ctx: *mut c_void) -> i32 { acquire(lock.cast(), ctx.cast(), false) }
/// Acquire one non-context lock with an interruptible wait. # C: O(1) uncontended
pub(super) extern "C" fn drm_modeset_lock_single_interruptible(lock: *mut c_void) -> i32 {
    if lock.is_null() { return -LINUX_EBUSY; }
    if crate::linux_sync::mutex_lock_interruptible(mutex(lock.cast())) != 0 { -LINUX_ERESTARTSYS } else { 0 }
}
/// Release one held modeset lock. # C: O(1)
pub(super) extern "C" fn drm_modeset_unlock(lock: *mut c_void) {
    if lock.is_null() { return; }
    let lock = lock.cast::<u8>(); let node = lock.wrapping_add(DRM_MODESET_LOCK_HEAD_OFF);
    if !list_empty(node) { list_del_init(node); }
    set_context(lock, core::ptr::null_mut()); crate::linux_sync::mutex_unlock(mutex(lock));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modeset_lock_retries_and_releases_through_its_context_list() {
        let mut lock = [0u8; DRM_MODESET_LOCK_SIZE]; let mut ctx = [0u8; DRM_MODESET_ACQUIRE_CTX_SIZE];
        drm_modeset_lock_init(lock.as_mut_ptr().cast()); drm_modeset_acquire_init(ctx.as_mut_ptr().cast(), 0);
        assert_eq!(drm_modeset_lock(lock.as_mut_ptr().cast(), ctx.as_mut_ptr().cast()), 0); assert_eq!(drm_modeset_lock(lock.as_mut_ptr().cast(), ctx.as_mut_ptr().cast()), 0);
        drm_modeset_drop_locks(ctx.as_mut_ptr().cast()); assert!(list_empty(lock.as_mut_ptr().wrapping_add(DRM_MODESET_LOCK_HEAD_OFF)));
    }
    #[test]
    fn trylock_context_tracks_a_successful_lock_for_the_standard_drop_path() {
        let mut lock = [0u8; DRM_MODESET_LOCK_SIZE]; let mut ctx = [0u8; DRM_MODESET_ACQUIRE_CTX_SIZE];
        drm_modeset_lock_init(lock.as_mut_ptr().cast()); drm_modeset_acquire_init(ctx.as_mut_ptr().cast(), 0);
        // SAFETY: ctx is a local stack array sized past DRM_MODESET_CTX_TRYLOCK_ONLY_OFF,
        // already initialized above and exclusively owned by this test.
        unsafe { write(ctx.as_mut_ptr().add(DRM_MODESET_CTX_TRYLOCK_ONLY_OFF).cast::<bool>(), true); }
        assert_eq!(drm_modeset_lock(lock.as_mut_ptr().cast(), ctx.as_mut_ptr().cast()), 0); drm_modeset_drop_locks(ctx.as_mut_ptr().cast());
        assert!(list_empty(lock.as_mut_ptr().wrapping_add(DRM_MODESET_LOCK_HEAD_OFF)));
    }
    #[test]
    fn modeset_lock_exports_are_present() { export_symbols(); for name in ["drm_modeset_acquire_init", "drm_modeset_lock", "drm_modeset_backoff", "drm_modeset_unlock"] { assert!(crate::symtab::is_exported(name)); } }
}
