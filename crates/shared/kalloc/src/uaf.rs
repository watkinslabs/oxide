// Use-after-free provenance queries the arch fault handler calls
// unconditionally: quarantine hit, evicted-block history, whole-list validity.

#[cfg(feature = "debug-heappoison")]
use core::sync::atomic::Ordering;

#[cfg(feature = "debug-heappoison")]
use crate::state::{KAlloc, GLOBAL_ALLOC};

/// Diagnostic (`debug-heappoison`): if `addr` points into a currently
/// quarantined (freed-but-poisoned) block, return its `(base, size, free_ip)`. A hit
/// means `addr` is a use-after-free; `size` names the victim's type. Always
/// present so the arch fault handler can call it unconditionally; returns
/// `None` (ring empty) when the feature is off.
/// # C: O(QN) when armed, O(1) otherwise
#[cfg(feature = "debug-heappoison")]
pub fn uaf_lookup(addr: u64) -> Option<(u64, u32, u64)> {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: `install_global` accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    let state = alloc.inner.lock();
    state.quarantine.lookup(addr)
}
/// Quarantine is not compiled in; no allocation is ever held. # C: O(1)
#[cfg(not(feature = "debug-heappoison"))]
pub fn uaf_lookup(_addr: u64) -> Option<(u64, u32, u64)> { None }

/// Diagnostic (`debug-heappoison`): provenance for an address that is no
/// longer quarantined (`uaf_lookup` misses it) but WAS recently evicted back
/// to the real hole list. Names "what used to live here" for a corrupt
/// free-list node discovered long after the fact, when the corrupting write
/// itself was never caught live. # C: O(EVICT_HISTORY_SLOTS)
#[cfg(feature = "debug-heappoison")]
pub fn evicted_lookup(addr: u64) -> Option<(u64, u32, u64)> {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: `install_global` accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    let state = alloc.inner.lock();
    state.holes.lookup_evicted(addr as usize).map(|(base, size, ip)| (base as u64, size, ip))
}
/// Evicted-block history is not compiled in. # C: O(1)
#[cfg(not(feature = "debug-heappoison"))]
pub fn evicted_lookup(_addr: u64) -> Option<(u64, u32, u64)> { None }

/// Diagnostic (`debug-heappoison`) bisection checkpoint: walk the installed
/// global allocator's free list right now and return the first corrupt
/// node's address, if any. Callers sprinkle this at boot checkpoints to
/// localize WHEN corruption first appears rather than where a later,
/// unrelated `alloc` happens to trip over it. `None` if uninstalled or intact.
/// # C: O(N)
#[cfg(feature = "debug-heappoison")]
pub fn validate_global() -> Option<usize> {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: `install_global` accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    alloc.validate_now()
}
