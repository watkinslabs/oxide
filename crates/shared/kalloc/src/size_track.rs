// Bounded live-allocation size tracker (`debug-dealloc-diag`).
//
// kalloc's free-list validation (`holes.rs`) only checks a freed range
// against OTHER FREE nodes and the registered backing region — it has no
// notion of "currently live" allocations at all. So a caller that calls
// `dealloc`/`GlobalAlloc::dealloc` with a `Layout` LARGER than what was
// actually allocated for that pointer gets silently accepted: the extra
// trailing bytes, which are still part of a live neighboring allocation,
// get folded into the free list and later overwritten by ordinary
// coalesce/carve bookkeeping. This tracker catches that class directly:
// record every alloc's exact carved size (blocks >= TRACK_MIN_SIZE only,
// to bound the table and stay off the hot small-alloc path), and assert
// at dealloc time that the caller's size matches exactly.
//
// Fixed-capacity open-addressing hash table, no recursive allocation
// (would deadlock — this lives inside the same lock as the hole list).
// Diagnostic-only; silently drops tracking on overflow (best-effort).

const TRACK_MIN_SIZE: usize = 512;
const TRACK_CAP: usize = 8192;
const EMPTY: usize = 0;
const TOMBSTONE: usize = usize::MAX;

pub struct SizeTrack {
    slots: [(usize, usize); TRACK_CAP],
}

impl SizeTrack {
    pub const fn new() -> Self { Self { slots: [(EMPTY, 0); TRACK_CAP] } }

    #[inline]
    fn idx(ptr: usize) -> usize {
        (ptr >> 4).wrapping_mul(2654435761) % TRACK_CAP
    }

    /// Record `ptr`'s carved allocation size, if >= `TRACK_MIN_SIZE`. # C: O(1) amortized
    pub fn record(&mut self, ptr: usize, size: usize) {
        if size < TRACK_MIN_SIZE || ptr == EMPTY { return; }
        let start = Self::idx(ptr);
        let mut first_free: Option<usize> = None;
        for i in 0..TRACK_CAP {
            let s = (start + i) % TRACK_CAP;
            let cur = self.slots[s].0;
            if cur == ptr { self.slots[s] = (ptr, size); return; }
            if cur == EMPTY || cur == TOMBSTONE {
                if first_free.is_none() { first_free = Some(s); }
                if cur == EMPTY { break; }
            }
        }
        if let Some(s) = first_free { self.slots[s] = (ptr, size); }
    }

    /// Remove and return `ptr`'s tracked size, or `None` if never recorded
    /// (untracked: below threshold, or the table was full at alloc time).
    /// # C: O(1) amortized
    pub fn take(&mut self, ptr: usize) -> Option<usize> {
        let start = Self::idx(ptr);
        for i in 0..TRACK_CAP {
            let s = (start + i) % TRACK_CAP;
            let cur = self.slots[s].0;
            if cur == ptr {
                let size = self.slots[s].1;
                self.slots[s] = (TOMBSTONE, 0);
                return Some(size);
            }
            if cur == EMPTY { return None; }
        }
        None
    }
}
