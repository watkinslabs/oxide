// Runtime in-kernel COW-corruption detector (`debug-cow` feature).
//
// Disambiguates the residual nondeterministic boot corruption (a random
// process SEGVs / a futex word reads 0 with no waker) that the hosted
// invariant harness cannot model (SMP timing / HHDM / real frame content
// / paths the mock `MmuOps` never exercises). OFF in prod: every public
// fn compiles to an empty body, the side table static does not exist, and
// the hot path emits zero bytes (`04§3` independence guarantee).
//
// Probes (read the report / module-doc for how to read each log line). All
// snapshot/verify variants share ONE side table keyed by frame PA; the
// per-slot `kind` selects the log tag so the classes stay independent:

const PAGE_ALIGN_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);
//   1a. ANON RO-shared checksum. `record` snapshots an anon frame the
//       moment `fork_cow` write-protects it; `check_write` re-verifies
//       before the COW copy, `check_free` before the buddy reclaims it. A
//       RO-shared frame whose content changed = a peer wrote it via a stale
//       writable TLB / wrong frame installed → `[COW-CORRUPT]`.
//   1b. FILE-backed private RO checksum (`record_file`). A private File page
//       W-stripped at fork, or installed RO at demand-fault, that mutates
//       before its COW copy → `[FILE-CORRUPT]` (cross-process shared-lib
//       `.data`/GOT/`.bss` corruption — the residual non-COW-anon SEGV
//       hypothesis under enforced CR0.WP).
//   1c. PAGE-CACHE-to-private checksum (`record_pagecache`). When a private
//       mapper copies from a frame-backed file's cache frame, that cache
//       frame must never change due to the private mapper's writes (they hit
//       the copy). A change, seen at the next private fault
//       (`check_pagecache`) or at free → `[PC-SHARED-WRITE]`.
//   2.  Task-struct integrity (`check_task`). Validates `current()`'s head
//       fields each fault entry; a clobbered task struct → `[TASK-CORRUPT]`.
//   3a. (pmm side) refcount/mapcount == live-PTE assert at free.
//   3b. (pmm side) 0xCC poison-on-free + dirtied-while-free check at alloc.
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

// Slot `kind` discriminator — selects which corruption class a snapshot
// belongs to so `verify` emits the right log line for the SAME side table:
//   1 = anon RO-shared (fork_cow W-strip)        → [COW-CORRUPT]
//   2 = file-private RO page (File COW / RO map)  → [FILE-CORRUPT]
//   3 = page-cache frame handed to a private map  → [PC-SHARED-WRITE]
#[cfg(feature = "debug-cow")]
const KIND_ANON: u32 = 1;
#[cfg(feature = "debug-cow")]
const KIND_FILE: u32 = 2;
#[cfg(feature = "debug-cow")]
const KIND_PC: u32 = 3;

#[cfg(feature = "debug-cow")]
struct Slot { pa: AtomicU64, cksum: AtomicU32, kind: AtomicU32 }

#[cfg(feature = "debug-cow")]
static TABLE: [Slot; SLOTS] = [const {
    Slot { pa: AtomicU64::new(0), cksum: AtomicU32::new(0), kind: AtomicU32::new(0) }
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
    let base = (hhdm + (pa & PAGE_ALIGN_MASK)) as *const u64;
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

/// Internal: snapshot `pa`'s content into its side-table slot under `kind`.
/// `only_if_new` preserves an existing snapshot of the SAME frame (used for
/// page-cache frames: the FIRST private mapper's content is the baseline a
/// later private write must not perturb); ANON/FILE re-snapshot in place
/// (the moment-of-W-strip content IS the new baseline).
#[cfg(feature = "debug-cow")]
#[inline]
fn record_kind(pa: u64, hhdm: u64, kind: u32, only_if_new: bool) {
    let pa = pa & PAGE_ALIGN_MASK;
    if pa == 0 { return; }
    let s = slot_for(pa);
    if only_if_new && s.pa.load(Ordering::Relaxed) == pa { return; }
    let c = checksum_impl(pa, hhdm);
    s.pa.store(pa, Ordering::Relaxed);
    s.cksum.store(c, Ordering::Relaxed);
    s.kind.store(kind, Ordering::Relaxed);
}

/// Snapshot `pa`'s content into the side table. Called by `fork_cow`
/// the instant an ANON frame is write-protected to RO-shared — from
/// here on the frame's bytes MUST NOT change until the owning AS COW-
/// copies it.
/// # C: O(512) word reads under debug-cow, O(1) otherwise.
#[inline]
pub fn record(pa: u64, hhdm: u64) {
    #[cfg(feature = "debug-cow")]
    { record_kind(pa, hhdm, KIND_ANON, false); }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = (pa, hhdm); }
}

/// Snapshot a FILE-backed private page the instant it becomes RO (fork_cow
/// W-strip of a private File VMA, or a RO private File demand-fault). From
/// here its bytes MUST NOT change until the owning AS COW-copies it — a
/// change before the COW (verified at `check_write`/`check_free`) means a
/// peer mutated a read-only file-private page (the cross-process shared-lib
/// `.data`/GOT/`.bss` corruption hypothesis) → [FILE-CORRUPT].
/// # C: O(512) word reads under debug-cow, O(1) otherwise.
#[inline]
pub fn record_file(pa: u64, hhdm: u64) {
    #[cfg(feature = "debug-cow")]
    { record_kind(pa, hhdm, KIND_FILE, false); }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = (pa, hhdm); }
}

/// Snapshot a PAGE-CACHE frame the instant it is handed to a PRIVATE mapper
/// (a private File fault copies FROM `pa` into a fresh frame). A private
/// write must land in the copy, never the cache frame — so this baseline
/// must NOT change. Re-verified at the next private fault (`check_pagecache`)
/// and at free → [PC-SHARED-WRITE]. `only_if_new`: keep the first mapper's
/// baseline across later mappers of the same page.
/// # C: O(512) word reads under debug-cow, O(1) otherwise.
#[inline]
pub fn record_pagecache(pa: u64, hhdm: u64) {
    #[cfg(feature = "debug-cow")]
    { record_kind(pa, hhdm, KIND_PC, true); }
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
        let pa = pa & PAGE_ALIGN_MASK;
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

/// Re-verify a PAGE-CACHE frame about to be handed to ANOTHER private
/// mapper, BEFORE the copy. If an earlier private mapper's write leaked
/// into the shared cache frame (no COW), its content changed since the
/// baseline snapshot:
///   `[PC-SHARED-WRITE] frame=PA va=VA pid=TID cpu=C expected=A got=B cache frame mutated by a private mapper`
/// Does NOT forget — the cache frame stays the baseline for further mappers.
/// # C: O(512) word reads under debug-cow, O(1) otherwise.
#[inline]
pub fn check_pagecache(pa: u64, va: u64, hhdm: u64, tid: u32, cpu: u32) {
    #[cfg(feature = "debug-cow")]
    { verify(pa, va, hhdm, tid, cpu, b" at=refault\n"); }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = (pa, va, hhdm, tid, cpu); }
}

/// Validate the running task's struct integrity from the page-fault hot
/// path. The task struct lives in the `sched` crate (not owned here), so
/// rather than add a magic field there we cheaply check self-consistency
/// of fields `mm` ALREADY reads via `current()`: `tid` within Linux
/// PID_MAX and the `name` `&'static str` fat-pointer (ptr non-null, len
/// bounded). A clobbered struct head fails these:
///   `[TASK-CORRUPT] tid=T canary=V reason=R`
/// where R: 1=tid out of range, 2=name ptr null, 3=name len absurd.
/// `name_ptr`/`name_len` are the caller-decomposed `t.name` fat pointer.
/// # C: O(1)
#[inline]
pub fn check_task(tid: u32, name_ptr: u64, name_len: u64) {
    #[cfg(feature = "debug-cow")]
    {
        // Oxide internal tid encoding (NOT Linux PID_MAX): kthreads/forks
        // come from `next_tid` (0x1000 upward), and init/PID1 is the reserved
        // sentinel 0xC0DE_0002 (registry.rs:170, smoke/elf.rs:124). So a tid
        // above Linux's 2^22 is NORMAL for init (every PID1 fault), not a
        // clobber — without this the probe false-positives on every systemd
        // page fault. Treat the reserved 0xC0DE_xxxx init/reserved band as
        // valid; only flag a tid that is neither a small monotonic tid nor in
        // the reserved band (true garbage from a clobbered task head).
        let reserved_init = (tid & 0xFFFF_0000) == 0xC0DE_0000;
        let reason: u32 =
            if tid > 0x40_0000 && !reserved_init { 1 }
            else if tid != 0 && name_ptr == 0 { 2 }
            else if name_len > 256 { 3 }
            else { 0 };
        if reason == 0 { return; }
        klog::write_raw(b"[TASK-CORRUPT] tid="); klog::write_dec_u64(tid as u64);
        klog::write_raw(b" canary=");            klog::write_hex_u64(name_ptr);
        klog::write_raw(b" len=");               klog::write_dec_u64(name_len);
        klog::write_raw(b" reason=");            klog::write_dec_u64(reason as u64);
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-cow"))]
    { let _ = (tid, name_ptr, name_len); }
}

#[cfg(feature = "debug-cow")]
fn verify(pa: u64, va: u64, hhdm: u64, tid: u32, cpu: u32, tail: &'static [u8]) {
    let pa = pa & PAGE_ALIGN_MASK;
    if pa == 0 { return; }
    let s = slot_for(pa);
    if s.pa.load(Ordering::Relaxed) != pa { return; } // not (or no longer) tracked
    let expected = s.cksum.load(Ordering::Relaxed);
    let got = checksum_impl(pa, hhdm);
    if got == expected { return; }
    // Same side table, three corruption classes — the slot's `kind`
    // selects the log tag so each probe reads independently in the log.
    let (head, mid): (&'static [u8], &'static [u8]) = match s.kind.load(Ordering::Relaxed) {
        KIND_FILE => (b"[FILE-CORRUPT] frame=", b" file-private RO page mutated"),
        KIND_PC   => (b"[PC-SHARED-WRITE] frame=", b" cache frame mutated by a private mapper"),
        _         => (b"[COW-CORRUPT] frame=", b""),
    };
    klog::write_raw(head);          klog::write_hex_u64(pa);
    klog::write_raw(b" va=");       klog::write_hex_u64(va);
    klog::write_raw(b" pid=");      klog::write_dec_u64(tid as u64);
    klog::write_raw(b" cpu=");      klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" expected="); klog::write_hex_u64(expected as u64);
    klog::write_raw(b" got=");      klog::write_hex_u64(got as u64);
    klog::write_raw(mid);
    klog::write_raw(tail);
}
