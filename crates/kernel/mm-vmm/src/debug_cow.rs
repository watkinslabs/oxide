// Runtime in-kernel COW-corruption detector (`debug-cow` feature).
//
// Disambiguates the residual nondeterministic boot corruption (a random
// process SEGVs / a futex word reads 0 with no waker) that the hosted
// invariant harness cannot model (SMP timing / HHDM / real frame content
// / paths the mock `MmuOps` never exercises). OFF in prod: every public
// fn compiles to an empty body, the side table static does not exist, and
// the hot path emits zero bytes (`04§3` independence guarantee).
//
// Three independent probes (read the report / module-doc for how to read
// each log line):
//   1. Per-frame content checksum. `record` snapshots an anon frame's
//      content the moment `fork_cow` write-protects it to RO-shared;
//      `check_write` re-verifies before the COW copy and `check_free`
//      re-verifies before the frame returns to the buddy. A RO-shared
//      frame whose content changed = a peer wrote it through a stale
//      writable TLB / a wrong frame was installed → `[COW-CORRUPT]`.
//   2. (pmm side) refcount/mapcount == live-PTE assert at free.
//   3. (pmm side) 0xCC poison-on-free + dirtied-while-free check at alloc.
//
// Side table: fixed, no-alloc, direct-mapped by pfn hash with
// overwrite-on-collision (best-effort sampling — a collision silently
// drops the older frame's snapshot, never a false positive). Atomics are
// Relaxed: a detector tolerates a torn read of a frame a peer is actively
// (incorrectly) writing — that torn value IS the corruption we report.

#[cfg(feature = "debug-cow")]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Side-table slot count. 16384 * 16 B = 256 KiB of `.bss` (debug-only).
#[cfg(feature = "debug-cow")]
const SLOTS: usize = 16384;

#[cfg(feature = "debug-cow")]
struct Slot { pa: AtomicU64, cksum: AtomicU32 }

#[cfg(feature = "debug-cow")]
static TABLE: [Slot; SLOTS] = [const {
    Slot { pa: AtomicU64::new(0), cksum: AtomicU32::new(0) }
}; SLOTS];

#[cfg(feature = "debug-cow")]
#[inline]
fn slot_for(pa: u64) -> &'static Slot {
    let pfn = pa >> 12;
    // Mix high bits down so adjacent frames don't all collide.
    let h = (pfn ^ (pfn >> 13) ^ (pfn >> 27)) as usize;
    &TABLE[h & (SLOTS - 1)]
}

/// FNV-1a-flavoured 32-bit checksum over a 4 KiB frame read through the
/// HHDM mirror. Folds 512 `u64` words (volatile so the compiler can't
/// hoist or elide a read of a frame a peer may be mutating). Any single
/// changed byte flips the digest. `# C: O(512)` word reads.
#[cfg(feature = "debug-cow")]
fn checksum_impl(pa: u64, hhdm: u64) -> u32 {
    if hhdm == 0 { return 0; }
    let base = (hhdm + (pa & !0xfff)) as *const u64;
    let mut h: u32 = 0x811c_9dc5;
    let mut i = 0usize;
    while i < 512 {
        // SAFETY: pa is a PMM-owned 4 KiB frame; its HHDM mirror at
        // `hhdm + pa` is kernel-readable for the full page; `i < 512`
        // keeps the 8-byte read inside the frame; volatile tolerates a
        // concurrent (buggy) peer writer — that is what we detect.
        let w = unsafe { core::ptr::read_volatile(base.add(i)) };
        // Fold the 8 bytes of the word, FNV-1a style.
        let mut b = 0;
        while b < 8 {
            let byte = ((w >> (b * 8)) & 0xff) as u32;
            h ^= byte;
            h = h.wrapping_mul(0x0100_0193);
            b += 1;
        }
        i += 1;
    }
    h
}

/// Public checksum helper (no-op → 0 when the feature is off).
/// # C: O(512) word reads under debug-cow, O(1) otherwise.
#[inline]
pub fn checksum(pa: u64, hhdm: u64) -> u32 {
    #[cfg(feature = "debug-cow")]
    { return checksum_impl(pa, hhdm); }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = (pa, hhdm); 0 }
}

/// Snapshot `pa`'s content into the side table. Called by `fork_cow`
/// the instant an ANON frame is write-protected to RO-shared — from
/// here on the frame's bytes MUST NOT change until the owning AS COW-
/// copies it.
/// # C: O(512) word reads under debug-cow, O(1) otherwise.
#[inline]
pub fn record(pa: u64, hhdm: u64) {
    #[cfg(feature = "debug-cow")]
    {
        let pa = pa & !0xfff;
        let c = checksum_impl(pa, hhdm);
        let s = slot_for(pa);
        s.pa.store(pa, Ordering::Relaxed);
        s.cksum.store(c, Ordering::Relaxed);
    }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = (pa, hhdm); }
}

/// Forget any recorded snapshot for `pa` (frame left RO-shared state:
/// became exclusive, was reused, or is being recycled).
/// # C: O(1)
#[inline]
pub fn forget(pa: u64) {
    #[cfg(feature = "debug-cow")]
    {
        let pa = pa & !0xfff;
        let s = slot_for(pa);
        if s.pa.load(Ordering::Relaxed) == pa { s.pa.store(0, Ordering::Relaxed); }
    }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = pa; }
}

/// Re-verify at a COW write-fault, BEFORE the copy. If `pa` carries a
/// recorded snapshot and its content changed while it was supposed to be
/// RO-shared, a peer mutated a read-only-shared page (stale writable TLB
/// on a not-shot-down PTE-change path, or the wrong frame was installed):
///   `[COW-CORRUPT] frame=PA va=VA pid=TID cpu=C expected=A got=B at=write`
/// Does NOT forget — the frame may still be RO-shared by other mappers,
/// each of which should re-verify on its own first write.
/// # C: O(512) word reads under debug-cow, O(1) otherwise.
#[inline]
pub fn check_write(pa: u64, va: u64, hhdm: u64, tid: u32, cpu: u32) {
    #[cfg(feature = "debug-cow")]
    { verify(pa, va, hhdm, tid, cpu, b" at=write\n"); }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = (pa, va, hhdm, tid, cpu); }
}

/// Re-verify when the frame is about to return to the buddy (refcount→0).
/// Same corruption class, observed at teardown:
///   `[COW-CORRUPT] frame=PA va=0 pid=TID cpu=C expected=A got=B at=free`
/// Forgets the slot afterwards (the frame is being recycled).
/// # C: O(512) word reads under debug-cow, O(1) otherwise.
#[inline]
pub fn check_free(pa: u64, hhdm: u64, tid: u32, cpu: u32) {
    #[cfg(feature = "debug-cow")]
    {
        verify(pa, 0, hhdm, tid, cpu, b" at=free\n");
        forget(pa);
    }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = (pa, hhdm, tid, cpu); }
}

#[cfg(feature = "debug-cow")]
fn verify(pa: u64, va: u64, hhdm: u64, tid: u32, cpu: u32, tail: &'static [u8]) {
    let pa = pa & !0xfff;
    if pa == 0 { return; }
    let s = slot_for(pa);
    if s.pa.load(Ordering::Relaxed) != pa { return; } // not (or no longer) tracked
    let expected = s.cksum.load(Ordering::Relaxed);
    let got = checksum_impl(pa, hhdm);
    if got == expected { return; }
    klog::write_raw(b"[COW-CORRUPT] frame="); klog::write_hex_u64(pa);
    klog::write_raw(b" va=");                 klog::write_hex_u64(va);
    klog::write_raw(b" pid=");                klog::write_dec_u64(tid as u64);
    klog::write_raw(b" cpu=");                klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" expected=");           klog::write_hex_u64(expected as u64);
    klog::write_raw(b" got=");                klog::write_hex_u64(got as u64);
    klog::write_raw(tail);
}
