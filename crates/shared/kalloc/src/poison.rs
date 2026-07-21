// Heap poison + quarantine (feature `debug-heappoison`) — a UAF localizer.
//
// On free, small blocks are overwritten with 0xEE and HELD in a fixed ring
// (`QUAR`) instead of returning to the hole list immediately, so a
// use-after-free READ observes 0xEE… (a garbage/huge value) DETERMINISTICALLY
// rather than intermittently seeing whatever a later reuse wrote. The block is
// really freed only when the ring wraps and evicts it. The x86 #UD/oops handler
// calls `uaf_lookup(reg)` on each GPR: a hit means that register points into a
// still-quarantined (freed) block, and the returned size names the victim type
// (ArcInner<File> vs ArcInner<Task> vs dentry/inode, by their distinct sizes).
//
// Diagnostic only (`docs/02`): never in a shipped profile. Bounds reuse-delay
// memory to QN * POISON_MAX worst case.

use core::alloc::Layout;
use core::ptr;

/// Blocks up to this size are poisoned/quarantined. MUST exceed sizeof(
/// ArcInner<Task>): Task alone is >4.6KB (rseq_ptr at offset 0x1180=4480, plus
/// trailing fields + Creds), so the old 4096 cap EXCLUDED every freed Task slot
/// from quarantine — and B712 evidence names freed Task slots as the residual
/// corruptor's prime victim, so poison was structurally blind to it. 8192 covers
/// Task (+Arc header +redzone) while still excluding huge page/DMA buffers.
pub const POISON_MAX: usize = 8192;
/// Ring depth. QN * POISON_MAX worst-case held-out memory. Large so blocks stay
/// quarantined long enough that a LONG-LIVED stale-pointer UAF write lands while
/// the block is still poisoned (the corruptor survives >2048 allocs).
pub const QUARANTINE_SLOTS: usize = 2048;
const POISON_BYTE: u8 = 0xEE;
const REDZONE_BYTE: u8 = 0xA5;
pub const REDZONE_BYTES: usize = 32;
/// Poison ONLY the leading bytes — an `ArcInner`'s strong+weak refcount words
/// live at offset 0/8, and the `#UD`/overflow victim is the strong count. A
/// reuse-UAF `Arc::clone`/`Weak::upgrade` on a quarantined block then reads
/// 0xEE… and traps, while freed objects' DATA fields (offset >=16) keep their
/// old valid bytes — so benign readers (e.g. udevd's device path) don't get
/// garbage and die early, which would remove the fork/openat/epoll storm that
/// triggers the bug. `min(POISON_HEAD, size)` bytes are filled.
const POISON_HEAD: usize = 16;

fn write_free_ip(free_ip: u64) {
    klog::write_raw(b" free_ip=");
    if free_ip == crate::caller::UNKNOWN_RETURN_IP {
        klog::write_raw(b"unknown");
    } else {
        klog::write_raw(b"0x");
        klog::write_hex_u64(free_ip);
    }
}

#[derive(Clone, Copy)]
struct Slot { base: u64, size: u32, align: u32, free_ip: u64, live: bool }
impl Slot { const EMPTY: Slot = Slot { base: 0, size: 0, align: 0, free_ip: crate::caller::UNKNOWN_RETURN_IP, live: false }; }

/// Quarantine belongs to exactly one `KAlloc` instance. Keeping it in the
/// allocator state prevents raw addresses from surviving a hosted allocator's
/// backing buffer and makes the free-list/quarantine ownership transition one
/// lock-serialized operation.
pub(crate) struct Quar { slots: [Slot; QUARANTINE_SLOTS], idx: usize, scan: usize }

impl Quar {
    pub(crate) const fn new() -> Self { Self { slots: [Slot::EMPTY; QUARANTINE_SLOTS], idx: 0, scan: 0 } }

    /// A quarantined extent is still allocator-owned, so a second release must
    /// be rejected before it can overwrite the block's eventual hole header.
    pub(crate) fn contains(&self, ptr: *mut u8, layout: Layout) -> bool {
        self.slots.iter().any(|s| s.live && s.base == ptr as u64 && s.size as usize == layout.size() && s.align as usize == layout.align())
    }

    pub(crate) fn lookup(&self, addr: u64) -> Option<(u64, u32, u64)> {
        self.slots.iter().find(|s| s.live && addr >= s.base && addr < s.base + s.size as u64).map(|s| (s.base, s.size, s.free_ip))
    }
}

/// Re-verify the poison head of `n` quarantined slots (round-robin from
/// `q.scan`). Any byte no longer 0xEE was WRITTEN after free (UAF write) — report
/// base/size(=type)/offset/value once. Catches a LONG-LIVED stale-pointer write
/// promptly (within QN/n frees of it happening), before eviction reclaims the
/// block. # C: O(n)
#[cfg(feature = "debug-heappoison")]
fn scan_window(q: &mut Quar, n: usize) {
    for _ in 0..n {
        let i = q.scan; q.scan = (i + 1) % QUARANTINE_SLOTS;
        let s = q.slots[i];
        if !s.live { continue; }
        // Scan DEEP, not just the 16B refcount head: observed corruption offsets
        // are 0x10/0x48/0x71 (16-113 bytes in), and a freed Task (>4.6KB) can be
        // scribbled at a much deeper pointer field, so scan a wide window.
        let head = core::cmp::min(1024, s.size as usize);
        for off in 0..head {
            // SAFETY: s.base/s.size from a prior alloc still owned by the ring.
            let b = unsafe { ptr::read((s.base as *const u8).add(off)) };
            if b != POISON_BYTE {
                klog::write_raw(b"[UAF-WRITE-SCAN] freed base=0x");
                klog::write_hex_u64(s.base);
                klog::write_raw(b" size="); klog::write_dec_u64(s.size as u64);
                klog::write_raw(b" off="); klog::write_dec_u64(off as u64);
                klog::write_raw(b" val=0x"); klog::write_hex_u64(b as u64);
                write_free_ip(s.free_ip);
                klog::write_raw(b"\n");
                // Re-poison so we don't spam the same slot every sweep.
                // SAFETY: same owned block; restoring the poison byte.
                unsafe { ptr::write_bytes((s.base as *mut u8).add(off), POISON_BYTE, 1); }
                break;
            }
        }
    }
}

/// Expand a caller layout with a trailing redzone. The user pointer is still the
/// allocation base; only the internal hole-list size grows. # C: O(1)
pub fn alloc_layout(layout: Layout) -> Option<Layout> {
    let size = layout.size().checked_add(REDZONE_BYTES)?;
    Layout::from_size_align(size, layout.align()).ok()
}

/// Arm the trailing redzone immediately after the caller-visible bytes. # C: O(R)
pub unsafe fn arm_redzone(ptr: *mut u8, layout: Layout) {
    // SAFETY: caller allocated using `alloc_layout(layout)`, so the redzone
    // range immediately after layout.size() is owned and writable.
    unsafe { ptr::write_bytes(ptr.add(layout.size()), REDZONE_BYTE, REDZONE_BYTES); }
}

/// Verify the trailing redzone before freeing/quarantining. A mismatch proves a
/// heap overflow by the owner of this allocation. # C: O(R)
pub unsafe fn check_redzone(ptr: *mut u8, layout: Layout) {
    for i in 0..REDZONE_BYTES {
        // SAFETY: caller allocated using `alloc_layout(layout)`; byte i lies in
        // the trailing redzone and is valid to read before deallocation.
        let got = unsafe { ptr::read(ptr.add(layout.size() + i)) };
        if got != REDZONE_BYTE {
            panic!("heap redzone corrupted");
        }
    }
}

/// Poison `[ptr, ptr+size)` with 0xEE and hold the block in the quarantine
/// ring (delaying reuse so a UAF read hits poison). Returns any older block
/// evicted from the ring for the caller to really free.
/// # SAFETY: `ptr`/`layout` came from a prior `alloc(layout)` and is no longer
/// borrowed; nothing may read the block until it is evicted and freed.
/// # C: O(1)
pub unsafe fn quarantine(q: &mut Quar, ptr: *mut u8, layout: Layout, free_ip: u64) -> Option<(*mut u8, Layout)> {
    // FULL-BLOCK poison (diagnostic): fill the ENTIRE freed block with 0xEE so a
    // UAF READ of any field (not just the refcount head) returns 0xEE.. → a
    // pointer field reads 0xeeeeeeeeeeeeeeee and the deref faults at ~0xeeee..
    // with the stale base pointer LIVE in a GPR → uaf_lookup (fault.rs) names the
    // block size (=victim type). Breaks benign freed-readers, but those faults
    // are also uaf_lookup hits — the FIRST hit names the corruptor's target.
    // SAFETY: caller guarantees the block is just-freed and owned by us.
    unsafe { ptr::write_bytes(ptr, POISON_BYTE, layout.size()); }
    let i = q.idx;
    q.idx = (i + 1) % QUARANTINE_SLOTS;
    let evict = if q.slots[i].live {
        let s = q.slots[i];
        // VERIFY the poison is intact before really freeing: any byte in the
        // poisoned head that is no longer 0xEE was WRITTEN while the block was
        // quarantined (freed) — a use-after-free WRITE. Since Arc/Weak refcounts
        // live at offset 0/8, a stale-Arc over-release scribbles a small count
        // here. Report base+size (size names the victim type) + the first
        // changed (offset,value) so the corruptor's target type is named.
        let head = core::cmp::min(POISON_HEAD, s.size as usize);
        // SAFETY: s.base/s.size came from a prior alloc still owned by the ring; reading the poisoned head is in-bounds.
        for off in 0..head {
            let b = unsafe { ptr::read((s.base as *const u8).add(off)) };
            if b != POISON_BYTE {
                #[cfg(feature = "debug-heappoison")]
                {
                    klog::write_raw(b"[UAF-WRITE] freed block base=0x");
                    klog::write_hex_u64(s.base);
                    klog::write_raw(b" size="); klog::write_dec_u64(s.size as u64);
                    klog::write_raw(b" off="); klog::write_dec_u64(off as u64);
                    klog::write_raw(b" val=0x"); klog::write_hex_u64(b as u64);
                    write_free_ip(s.free_ip);
                    klog::write_raw(b"\n");
                }
                break;
            }
        }
        // SAFETY: (size,align) were split from a valid Layout on insert; reconstructing the same Layout is in-bounds by construction.
        Some((s.base as *mut u8, unsafe { Layout::from_size_align_unchecked(s.size as usize, s.align as usize) }))
    } else { None };
    q.slots[i] = Slot { base: ptr as u64, size: layout.size() as u32, align: layout.align() as u32, free_ip, live: true };
    // Re-verify a window of older quarantined blocks so a long-lived UAF write is
    // caught promptly (full sweep every QN/32 frees).
    #[cfg(feature = "debug-heappoison")]
    scan_window(q, 128);
    evict
}
