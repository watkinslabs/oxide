// debug-efence (C213): small-object page-per-object guard-arena routing.
// kalloc has no HAL dep, so the arena lives in the `efence` crate and installs
// its alloc/free callbacks + VA window here (mirrors the grow-hook pattern).

use core::sync::atomic::{AtomicU64, Ordering};

/// Fence a `size`-class object one-per-guarded-page. Returns null when not
/// fenceable / arena momentarily out (kalloc then uses its normal heap).
pub type EfAllocFn = fn(size: usize, align: usize, alloc_ip: u64) -> *mut u8;
/// Free a fenced object (ptr already known in-window). Returns true = kalloc
/// must NOT run its own free path for this ptr.
pub type EfFreeFn = fn(ptr: *mut u8, free_ip: u64) -> bool;

static ALLOC: AtomicU64 = AtomicU64::new(0);
static FREE: AtomicU64 = AtomicU64::new(0);
static LO: AtomicU64 = AtomicU64::new(0);
static HI: AtomicU64 = AtomicU64::new(0);

/// Install the `efence` arena's alloc/free callbacks + VA window `[lo, hi)`.
/// Called once by `efence::init` after the arena is live. # C: O(1)
pub fn install_efence(alloc: EfAllocFn, free: EfFreeFn, lo: u64, hi: u64) {
    LO.store(lo, Ordering::Release);
    HI.store(hi, Ordering::Release);
    ALLOC.store(alloc as usize as u64, Ordering::Release);
    FREE.store(free as usize as u64, Ordering::Release);
}

/// alloc-path consult. Null unless a hook is installed AND it fenced it.
/// # C: O(1) + hook cost
#[inline]
pub(crate) fn try_alloc(size: usize, align: usize, alloc_ip: u64) -> *mut u8 {
    let raw = ALLOC.load(Ordering::Acquire);
    if raw == 0 { return core::ptr::null_mut(); }
    // SAFETY: `raw` was stored only by `install` from a valid `EfAllocFn`;
    // the round-trip cast restores the fn-pointer ABI.
    let f: EfAllocFn = unsafe { core::mem::transmute(raw as usize) };
    f(size, align, alloc_ip)
}

/// dealloc-path consult. Fast range-reject (no arena lock) before the hook.
/// # C: O(1) + hook cost
#[inline]
pub(crate) fn try_free(ptr: *mut u8, free_ip: u64) -> bool {
    let p = ptr as u64;
    if p < LO.load(Ordering::Acquire) || p >= HI.load(Ordering::Acquire) { return false; }
    let raw = FREE.load(Ordering::Acquire);
    if raw == 0 { return false; }
    // SAFETY: `raw` was stored only by `install` from a valid `EfFreeFn`.
    let f: EfFreeFn = unsafe { core::mem::transmute(raw as usize) };
    f(ptr, free_ip)
}
