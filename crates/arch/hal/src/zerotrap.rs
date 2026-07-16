// DIAG (debug-zerotrap): armed-frame zero-write trap. The exit-127 hunt
// proved a correctly-filled file page is zeroed IN PLACE by some kernel
// zeroing site. Every `write_bytes(dst, 0, n)` in the kernel that can touch
// a PMM frame calls `trap(dst, n)` first; when the destination overlaps an
// armed frame's HHDM mirror it logs the CALL SITE (#[track_caller]) + tid —
// naming the zeroer directly. Feature-off: every fn is an empty inline.

#[cfg(feature = "debug-zerotrap")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "debug-zerotrap")]
const SLOTS: usize = 256;
#[cfg(feature = "debug-zerotrap")]
const PAGE_MASK: u64 = !(PAGE_SIZE_BYTES - 1);
#[cfg(feature = "debug-zerotrap")]
static ARMED: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
#[cfg(feature = "debug-zerotrap")]
static HHDM: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug-zerotrap")]
static TID_HOOK: AtomicU64 = AtomicU64::new(0);

/// Arm a watch on frame `pa` (page-aligned). `hhdm` = HHDM offset so the
/// trap can compare kernel-mirror destinations. # C: O(SLOTS)
#[inline]
pub fn arm(pa: u64, hhdm: u64) {
    #[cfg(feature = "debug-zerotrap")]
    {
        HHDM.store(hhdm, Ordering::Release);
        for s in ARMED.iter() {
            if s.compare_exchange(0, pa & PAGE_MASK, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return;
            }
        }
    }
    #[cfg(not(feature = "debug-zerotrap"))]
    { let _ = (pa, hhdm); }
}

/// Disarm the watch on `pa` (frame legitimately freed/repurposed). # C: O(SLOTS)
#[inline]
#[track_caller]
pub fn disarm(pa: u64) {
    #[cfg(feature = "debug-zerotrap")]
    {
        let key = pa & PAGE_MASK;
        for s in ARMED.iter() {
            if s.compare_exchange(key, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                // A watched frame leaving service — legit at process
                // teardown; a PREMATURE free (still mapped) shows here too,
                // with the freeing call site named.
                let loc = core::panic::Location::caller();
                klog::write_raw(b"[ZEROTRAP-FREE] pa=");
                klog::write_hex_u64(key);
                klog::write_raw(b" at ");
                klog::write_raw(loc.file().as_bytes());
                klog::write_raw(b":");
                klog::write_dec_u64(loc.line() as u64);
                klog::write_raw(b"\n");
            }
        }
    }
    #[cfg(not(feature = "debug-zerotrap"))]
    { let _ = pa; }
}

/// Install a "current tid" getter so the trap can name the running task
/// without hal depending on sched. # C: O(1)
#[inline]
pub fn set_tid_hook(f: fn() -> u32) {
    #[cfg(feature = "debug-zerotrap")]
    TID_HOOK.store(f as usize as u64, Ordering::Release);
    #[cfg(not(feature = "debug-zerotrap"))]
    { let _ = f; }
}

/// Call BEFORE zeroing `[dst, dst+len)`. Logs [ZEROTRAP] with the caller's
/// file:line + tid when the destination overlaps an armed frame's HHDM
/// mirror. # C: O(SLOTS)
#[inline]
#[track_caller]
pub fn trap(dst: *const u8, len: usize) {
    #[cfg(feature = "debug-zerotrap")]
    {
        let hhdm = HHDM.load(Ordering::Acquire);
        if hhdm == 0 { return; }
        let d0 = dst as u64;
        let d1 = d0.saturating_add(len as u64);
        if d0 < hhdm { return; } // not an HHDM-mirror write
        for s in ARMED.iter() {
            let pa = s.load(Ordering::Acquire);
            if pa == 0 { continue; }
            let f0 = hhdm + pa;
            let f1 = f0 + PAGE_SIZE_BYTES;
            if d0 < f1 && d1 > f0 {
                let loc = core::panic::Location::caller();
                klog::write_raw(b"[ZEROTRAP] pa=");
                klog::write_hex_u64(pa);
                klog::write_raw(b" dst=");
                klog::write_hex_u64(d0);
                klog::write_raw(b" len=");
                klog::write_hex_u64(len as u64);
                klog::write_raw(b" tid=");
                let h = TID_HOOK.load(Ordering::Acquire);
                let tid = if h != 0 {
                    // SAFETY: h was stored from a `fn() -> u32` in set_tid_hook.
                    (unsafe { core::mem::transmute::<u64, fn() -> u32>(h) })()
                } else { 0 };
                klog::write_dec_u64(tid as u64);
                klog::write_raw(b" at ");
                klog::write_raw(loc.file().as_bytes());
                klog::write_raw(b":");
                klog::write_dec_u64(loc.line() as u64);
                klog::write_raw(b"\n");
            }
        }
    }
    #[cfg(not(feature = "debug-zerotrap"))]
    { let _ = (dst, len); }
}

/// True iff `pa`'s frame is currently armed. # C: O(SLOTS)
#[inline]
pub fn is_armed(pa: u64) -> bool {
    #[cfg(feature = "debug-zerotrap")]
    {
        let key = pa & PAGE_MASK;
        for s in ARMED.iter() {
            if s.load(Ordering::Acquire) == key { return true; }
        }
        false
    }
    #[cfg(not(feature = "debug-zerotrap"))]
    { let _ = pa; false }
}

/// Call from the buddy allocator's alloc/free choke points: logs when an
/// ARMED (live, in-service) frame passes through — an armed frame being
/// FREED or RE-ALLOCATED is the double-allocation smoking gun, with the
/// call site named. # C: O(SLOTS)
#[inline]
#[track_caller]
pub fn trap_buddy(pa: u64, what: &'static [u8]) {
    #[cfg(feature = "debug-zerotrap")]
    {
        if !is_armed(pa) { return; }
        let loc = core::panic::Location::caller();
        klog::write_raw(b"[BUDDY-ARMED-");
        klog::write_raw(what);
        klog::write_raw(b"] pa=");
        klog::write_hex_u64(pa & PAGE_MASK);
        klog::write_raw(b" tid=");
        let h = TID_HOOK.load(Ordering::Acquire);
        let tid = if h != 0 {
            // SAFETY: h stored from a `fn() -> u32` in set_tid_hook.
            (unsafe { core::mem::transmute::<u64, fn() -> u32>(h) })()
        } else { 0 };
        klog::write_dec_u64(tid as u64);
        klog::write_raw(b" at ");
        klog::write_raw(loc.file().as_bytes());
        klog::write_raw(b":");
        klog::write_dec_u64(loc.line() as u64);
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-zerotrap"))]
    { let _ = (pa, what); }
}

/// Read the installed current-tid hook (0 pre-install or feature-off). # C: O(1)
#[inline]
pub fn cur_tid() -> u32 {
    #[cfg(feature = "debug-zerotrap")]
    {
        let h = TID_HOOK.load(Ordering::Acquire);
        if h == 0 { return 0; }
        // SAFETY: h stored from a `fn() -> u32` in set_tid_hook.
        (unsafe { core::mem::transmute::<u64, fn() -> u32>(h) })()
    }
    #[cfg(not(feature = "debug-zerotrap"))]
    { 0 }
}
