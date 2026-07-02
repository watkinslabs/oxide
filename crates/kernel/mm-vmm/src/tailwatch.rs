// DIAG (debug-atexit): sentinel frame watch. The exit-127 hunt proved the
// corruption target is deterministic (a library's EOF-straddling RW tail
// page — filled correctly, zeroed IN PLACE later) while the victim process
// is random. `record` stashes the filled frame at fill time; `check` is
// called from the fault-dispatch hot path and logs [TAILZAP] with the
// current task the moment the sentinel bytes flip to zero — naming the
// window in which the zeroing write happened.

use core::sync::atomic::{AtomicU64, Ordering};

const SLOTS: usize = 16;
/// Watched frame PAs (0 = empty). One slot per concurrent mapper of the
/// sentinel page (each process gets a private fill frame).
static PA: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// HHDM offset captured at record time (same for all slots).
static HHDM: AtomicU64 = AtomicU64::new(0);

/// Offset within the sentinel page that goes zero in the corrupted case
/// (observed `at=0x100` in every [MAPZERO] hit) and its expected non-zero
/// content width.
const OFF: usize = 0x100;

/// Register a freshly-filled sentinel frame. # C: O(SLOTS)
pub fn record(pa: u64, hhdm: u64) {
    HHDM.store(hhdm, Ordering::Release);
    // Sanity: only watch frames whose sentinel window is non-zero after fill.
    let base = (hhdm + pa) as *const u8;
    // SAFETY: pa is the just-filled fill frame (owned by the fault path);
    // HHDM mirror readable; OFF+32 within the page.
    let nz = unsafe { (0..32).any(|i| core::ptr::read_volatile(base.add(OFF + i)) != 0) };
    if !nz { return; }
    for s in PA.iter() {
        if s.compare_exchange(0, pa, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            klog::write_raw(b"[TAILWATCH] armed pa=");
            klog::write_hex_u64(pa);
            klog::write_raw(b"\n");
            return;
        }
    }
}

/// Stop watching `pa` (frame freed / repurposed legitimately). # C: O(SLOTS)
pub fn forget(pa: u64) {
    for s in PA.iter() {
        let _ = s.compare_exchange(pa, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Re-verify every armed sentinel; log + disarm on a zero flip. Called from
/// the fault-dispatch entry (hot during the boot fork/exec storm, so the
/// detection window is tight). `tid` is the current task. # C: O(SLOTS)
pub fn check(tid: u32) {
    let hhdm = HHDM.load(Ordering::Acquire);
    if hhdm == 0 { return; }
    for s in PA.iter() {
        let pa = s.load(Ordering::Acquire);
        if pa == 0 { continue; }
        let base = (hhdm + pa) as *const u8;
        // SAFETY: armed sentinel frames are live fill frames; HHDM readable.
        let all_zero = unsafe { (0..32).all(|i| core::ptr::read_volatile(base.add(OFF + i)) == 0) };
        if all_zero {
            klog::write_raw(b"[TAILZAP] pa=");
            klog::write_hex_u64(pa);
            klog::write_raw(b" seen-zero in tid=");
            klog::write_dec_u64(tid as u64);
            klog::write_raw(b"\n");
            s.store(0, Ordering::Release);
        }
    }
}
