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

use sync::{KMalloc, Spinlock};

/// Only small blocks are poisoned/quarantined — Arc inners (File/Task/dentry/
/// inode/superblock) all fall under this; large buffers free normally so the
/// held-memory bound stays small.
pub const POISON_MAX: usize = 4096;
/// Ring depth. QN * POISON_MAX (= 8 MiB) is the worst-case held-out memory.
const QN: usize = 2048;
const POISON_BYTE: u8 = 0xEE;
/// Poison ONLY the leading bytes — an `ArcInner`'s strong+weak refcount words
/// live at offset 0/8, and the `#UD`/overflow victim is the strong count. A
/// reuse-UAF `Arc::clone`/`Weak::upgrade` on a quarantined block then reads
/// 0xEE… and traps, while freed objects' DATA fields (offset >=16) keep their
/// old valid bytes — so benign readers (e.g. udevd's device path) don't get
/// garbage and die early, which would remove the fork/openat/epoll storm that
/// triggers the bug. `min(POISON_HEAD, size)` bytes are filled.
const POISON_HEAD: usize = 16;

#[derive(Clone, Copy)]
struct Slot { base: u64, size: u32, align: u32, live: bool }
impl Slot { const EMPTY: Slot = Slot { base: 0, size: 0, align: 0, live: false }; }

struct Quar { slots: [Slot; QN], idx: usize }

static QUAR: Spinlock<Quar, KMalloc> = Spinlock::new(Quar { slots: [Slot::EMPTY; QN], idx: 0 });

/// Poison `[ptr, ptr+size)` with 0xEE and hold the block in the quarantine
/// ring (delaying reuse so a UAF read hits poison). Returns any older block
/// evicted from the ring for the caller to really free.
/// # SAFETY: `ptr`/`layout` came from a prior `alloc(layout)` and is no longer
/// borrowed; nothing may read the block until it is evicted and freed.
/// # C: O(1)
pub unsafe fn quarantine(ptr: *mut u8, layout: Layout) -> Option<(*mut u8, Layout)> {
    // SAFETY: caller guarantees the block is just-freed and owned by us; fill only the leading refcount words so a UAF Arc/Weak deref traps while data fields stay valid (avoids breaking benign freed-memory readers).
    unsafe { ptr::write_bytes(ptr, POISON_BYTE, core::cmp::min(POISON_HEAD, layout.size())); }
    let mut q = QUAR.lock();
    let i = q.idx;
    q.idx = (i + 1) % QN;
    let evict = if q.slots[i].live {
        let s = q.slots[i];
        // SAFETY: (size,align) were split from a valid Layout on insert; reconstructing the same Layout is in-bounds by construction.
        Some((s.base as *mut u8, unsafe { Layout::from_size_align_unchecked(s.size as usize, s.align as usize) }))
    } else { None };
    q.slots[i] = Slot { base: ptr as u64, size: layout.size() as u32, align: layout.align() as u32, live: true };
    evict
}

/// If `addr` falls inside a currently-quarantined (freed) block, return its
/// `(base, size)`. A hit = the faulting pointer references freed memory (UAF);
/// `size` names the victim type by its allocation size.
/// # C: O(QN)
pub fn uaf_lookup(addr: u64) -> Option<(u64, u32)> {
    let q = QUAR.lock();
    for s in q.slots.iter() {
        if s.live && addr >= s.base && addr < s.base + s.size as u64 {
            return Some((s.base, s.size));
        }
    }
    None
}
