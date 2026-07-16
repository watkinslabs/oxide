// DIAG (debug-atexit): sentinel frame watch. The exit-127 hunt proved the
// corruption target class is deterministic (EOF-straddling writable file-page
// fills — filled correctly, zeroed IN PLACE later) while the victim process is
// random. `record` stashes the filled frame + a full-page checksum at fill
// time; `check` (fault-dispatch hot path) re-verifies a rotating sample and
// logs [TAILZAP] with the current task + first-diff offset the moment a
// watched page changes while its owner never legitimately wrote it (these are
// pages the OWNER also may write — relocations! — so a TAILZAP is a LEAD, and
// all-zero content is the smoking gun). hal::zerotrap::arm is address-based
// and catches instrumented kernel write_bytes zeroing directly.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const PAGE_ALIGN_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);
const SLOTS: usize = 256;
static PA:  [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static SUM: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// Owning AS root (CR3 pa) captured at fill time — distinguishes the owner's
/// own legitimate free (silent) from a FOREIGN root freeing a live frame.
static OWNER: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static HHDM: AtomicU64 = AtomicU64::new(0);
static RR: AtomicUsize = AtomicUsize::new(0);
static CK: AtomicUsize = AtomicUsize::new(0);

/// FNV-ish full-page checksum over the HHDM mirror. # C: O(4K)
fn page_sum(hhdm: u64, pa: u64) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let words = (hhdm + pa) as *const u64;
    // SAFETY: pa is a live watched frame; HHDM mirror readable; 4 KiB.
    unsafe {
        for i in 0..512 {
            h ^= core::ptr::read_volatile(words.add(i));
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

/// Register a freshly-filled sentinel frame owned by AS root `owner`.
/// # C: O(SLOTS)
pub fn record(pa: u64, hhdm: u64, owner: u64) {
    HHDM.store(hhdm, Ordering::Release);
    hal::zerotrap::arm(pa, hhdm);
    let sum = page_sum(hhdm, pa);
    for i in 0..SLOTS {
        if PA[i].compare_exchange(0, pa, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            SUM[i].store(sum, Ordering::Release);
            OWNER[i].store(owner, Ordering::Release);
            return;
        }
    }
    let i = RR.fetch_add(1, Ordering::Relaxed) % SLOTS;
    PA[i].store(pa, Ordering::Release);
    SUM[i].store(sum, Ordering::Release);
    OWNER[i].store(owner, Ordering::Release);
}

/// Owning AS root of an armed frame, if watched. # C: O(SLOTS)
pub fn owner_of(pa: u64) -> Option<u64> {
    let key = pa & PAGE_ALIGN_MASK;
    for i in 0..SLOTS {
        if PA[i].load(Ordering::Acquire) == key {
            return Some(OWNER[i].load(Ordering::Acquire));
        }
    }
    None
}

/// The frame's refcount hit ZERO under context root `ctx_root` (the dying AS
/// in as_teardown; the caller's own root otherwise). Owner-context final
/// release = legit, clear silently. A FOREIGN root taking the LAST reference
/// = the free-while-mapped bug — name both roots. # C: O(SLOTS)
pub fn note_final_free(pa: u64, ctx_root: u64) {
    let key = pa & PAGE_ALIGN_MASK;
    for i in 0..SLOTS {
        if PA[i].load(Ordering::Acquire) != key { continue; }
        let owner = OWNER[i].load(Ordering::Acquire);
        if owner != ctx_root {
            klog::write_raw(b"[FWM-FREE] pa=");
            klog::write_hex_u64(key);
            klog::write_raw(b" owner-root=");
            klog::write_hex_u64(owner);
            klog::write_raw(b" freed-by-root=");
            klog::write_hex_u64(ctx_root);
            klog::write_raw(b"\n");
        }
        PA[i].store(0, Ordering::Release);
        hal::zerotrap::disarm(key);
    }
}

/// Stop watching `pa` (frame freed / repurposed legitimately). # C: O(SLOTS)
pub fn forget(pa: u64) {
    hal::zerotrap::disarm(pa);
    for s in PA.iter() {
        let _ = s.compare_exchange(pa, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Re-verify a rotating sample of watched frames (8 per call → full sweep
/// every 32 fault entries during the boot storm). A changed page that is now
/// ALL-ZERO in its first 512 bytes is the corruption signature; a changed
/// page with content = owner wrote it legitimately (relocations) → re-baseline
/// silently. # C: O(8 × 4K)
pub fn check(tid: u32) {
    let hhdm = HHDM.load(Ordering::Acquire);
    if hhdm == 0 { return; }
    let start = CK.fetch_add(8, Ordering::Relaxed);
    for k in 0..8usize {
        let i = (start + k) % SLOTS;
        let pa = PA[i].load(Ordering::Acquire);
        if pa == 0 { continue; }
        let want = SUM[i].load(Ordering::Acquire);
        let got = page_sum(hhdm, pa);
        if got == want { continue; }
        // Changed. Zero-signature?
        let base = (hhdm + pa) as *const u64;
        // SAFETY: live watched frame; HHDM readable.
        let zero64 = unsafe { (0..64).all(|w| core::ptr::read_volatile(base.add(w)) == 0) };
        if zero64 {
            klog::write_raw(b"[TAILZAP] pa=");
            klog::write_hex_u64(pa);
            klog::write_raw(b" ZEROED, seen in tid=");
            klog::write_dec_u64(tid as u64);
            klog::write_raw(b"\n");
            PA[i].store(0, Ordering::Release);
            hal::zerotrap::disarm(pa);
        } else {
            // Legit owner write (relocation etc.) — new baseline.
            SUM[i].store(got, Ordering::Release);
        }
    }
}

/// Install-lineage log for the corruption target class (EOF-straddling file
/// pages): every PTE install prints its origin so a corrupted (ino,foff) at
/// exit has its full history in the boot log. # C: O(1)
pub fn log_install(tag: &'static [u8], ino: u64, foff: u64, va: u64, pa: u64, root: u64) {
    klog::write_raw(b"[INST ");
    klog::write_raw(tag);
    klog::write_raw(b"] ino=");
    klog::write_hex_u64(ino);
    klog::write_raw(b" foff=");
    klog::write_hex_u64(foff);
    klog::write_raw(b" va=");
    klog::write_hex_u64(va);
    klog::write_raw(b" pa=");
    klog::write_hex_u64(pa);
    klog::write_raw(b" root=");
    klog::write_hex_u64(root);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(crate::tailwatch::cur_tid() as u64);
    klog::write_raw(b"\n");
}

/// Current tid via the sched hook installed for zerotrap (avoids a sched dep
/// in this crate). Returns 0 pre-hook. # C: O(1)
pub fn cur_tid() -> u32 { hal::zerotrap::cur_tid() }
