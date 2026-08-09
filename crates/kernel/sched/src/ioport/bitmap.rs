// Per-task x86 I/O permission map — the software half of `ioperm(2)`.
//
// One bit per port, SET = denied, CLEAR = permitted, matching the hardware
// encoding the TSS window is loaded with verbatim. A fresh map denies
// everything; `ioperm(from, num, 1)` clears a range.
//
// Ungated on purpose: every decision here (range edit, max-byte window,
// all-denied detection, copy-on-write) is testable hosted, and the kernel
// build only adds the TSS store on top.

use alloc::boxed::Box;
use alloc::vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Ports an x86 I/O permission map covers: the entire 16-bit port space.
pub const IO_BITMAP_BITS: u64 = 65536;
/// Bytes of permission bits.
pub const IO_BITMAP_BYTES: usize = (IO_BITMAP_BITS / 8) as usize;
/// `u64` words of permission bits.
pub const IO_BITMAP_LONGS: usize = IO_BITMAP_BYTES / core::mem::size_of::<u64>();

/// Monotonic revision stamp handed to each edited map. A CPU that already
/// holds revision N in its TSS skips the copy when the same map comes back,
/// which is what keeps a port-using task off an 8 KiB memcpy per switch.
/// Starts at 1 so it can never collide with a CPU's never-copied sentinel.
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// A task's port permissions. Shared between a parent and its children until
/// one of them edits it (`Arc` refcount > 1 ⇒ copy first), exactly the
/// reference's `refcount_t`-plus-`kmemdup` scheme.
#[derive(Clone)]
pub struct IoBitmap {
    /// Revision of this content, for the per-CPU TSS copy elision.
    pub sequence: u64,
    /// Leading bytes that carry any permitted bit. The TSS copy need not go
    /// further, since everything beyond is denied and the window's resting
    /// state is deny-all.
    pub max: u32,
    /// `IO_BITMAP_LONGS` words, set bit = denied. Heap-resident: 8 KiB is far
    /// too much to carry through a stack frame.
    bits: Box<[u64]>,
}

impl IoBitmap {
    /// A map that denies every port — the state `ioperm` starts from before
    /// its first `turn_on` range.
    /// # C: O(IO_BITMAP_LONGS)
    pub fn denied_all() -> Self {
        Self { sequence: next_sequence(), max: 0, bits: vec![u64::MAX; IO_BITMAP_LONGS].into_boxed_slice() }
    }

    /// Permission bits as the byte image the TSS window takes.
    /// # C: O(1)
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: `bits` is a live `IO_BITMAP_LONGS`-word allocation; `u64` has
        // no padding or invalid bit patterns, so reading it as bytes is a
        // reinterpret of initialised memory with a strictly smaller alignment.
        unsafe { core::slice::from_raw_parts(self.bits.as_ptr() as *const u8, IO_BITMAP_BYTES) }
    }

    /// True when port `port` may be accessed from user mode under this map.
    /// # C: O(1)
    pub fn permits(&self, port: u64) -> bool {
        if port >= IO_BITMAP_BITS { return false; }
        let (w, b) = ((port / 64) as usize, port % 64);
        self.bits[w] & (1u64 << b) == 0
    }

    /// Apply one `ioperm` range: `turn_on` clears (permits) the bits, else it
    /// sets (denies) them. Callers have already validated the range.
    /// # C: O(num)
    pub fn set_range(&mut self, from: u64, num: u64, turn_on: bool) {
        for p in from..from.saturating_add(num).min(IO_BITMAP_BITS) {
            let (w, b) = ((p / 64) as usize, p % 64);
            if turn_on { self.bits[w] &= !(1u64 << b); } else { self.bits[w] |= 1u64 << b; }
        }
    }

    /// Recompute the leading-byte window: `Some(max)` when some port is still
    /// permitted, `None` when the map denies everything and should be dropped.
    ///
    /// Deliberately the reference's simple scan of every word rather than a
    /// cached high-water mark — `ioperm` is not on any hot path, and a cached
    /// bound is exactly the thing that goes stale and leaves a port open.
    /// # C: O(IO_BITMAP_LONGS)
    pub fn recompute_max(&self) -> Option<u32> {
        let mut last = None;
        for (i, w) in self.bits.iter().enumerate() { if *w != u64::MAX { last = Some(i); } }
        last.map(|i| ((i + 1) * core::mem::size_of::<u64>()) as u32)
    }

    /// Stamp this content with a fresh revision so every CPU re-copies it.
    /// # C: O(1)
    pub fn restamp(&mut self) { self.sequence = next_sequence(); }
}

/// Next map revision. Wrapping is not a correctness concern at one increment
/// per `ioperm` call, but the zero sentinel is skipped so a wrapped counter
/// can never look like "this CPU has never copied a map".
/// # C: O(1)
fn next_sequence() -> u64 {
    let s = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    if s == 0 { SEQUENCE.fetch_add(1, Ordering::Relaxed) } else { s }
}
