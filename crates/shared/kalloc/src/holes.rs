// Sorted hole-list allocator (linked_list_allocator-style).
//
// Each free region carries a header at its start: `{ size, next }`. The
// list is kept sorted by address so dealloc can coalesce adjacent
// regions in `O(N)`. First-fit on alloc.
//
// Bounded waste: up to `MIN_HOLE_SIZE - 1` bytes can be absorbed into
// an allocation when the back padding is too small to host a fresh
// header — those bytes are lost until an adjacent free merges them
// back in. Over a 16 MiB heap this is negligible (`< 1 MiB` worst case
// across `≥ 64 K` allocations) and the allocator is replaced by a
// PMM-backed slab router (`12§2`) once a kernel binary stage exists.

use core::alloc::Layout;
use core::cmp::max;
use core::mem;
use core::ptr::NonNull;

/// Each free region begins with this header. `size` is the region's
/// total byte length including the header itself.
#[repr(C)]
pub struct HoleHdr {
    pub size: usize,
    pub next: Option<NonNull<HoleHdr>>,
}

/// Minimum size of a free region (must hold at least the header).
pub const MIN_HOLE_SIZE: usize = mem::size_of::<HoleHdr>();
/// Minimum alignment of a free region's start.
pub const MIN_HOLE_ALIGN: usize = mem::align_of::<HoleHdr>();

/// Round `addr` up to the next multiple of `align`. `align` must be a
/// power of two.
#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

/// Sorted singly-linked list of free regions. The list is owned by
/// `HoleList`; `KAlloc` wraps it in a `Spinlock`.
pub struct HoleList {
    /// Sentinel header so all "list head" updates go through `next`,
    /// without a separate `head: Option<...>` case.
    first: HoleHdr,
}

// SAFETY: `HoleList` mediates exclusive access to the heap region via
// the outer `Spinlock`; the `NonNull<HoleHdr>` chain only points into
// memory owned by the list, which the user reserves once at init.
unsafe impl Send for HoleList {}

impl HoleList {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { first: HoleHdr { size: 0, next: None } }
    }

    /// Insert a free region `[addr, addr + size)` into the list.
    ///
    /// # SAFETY: caller asserts the byte range is valid, exclusively
    /// owned by this allocator, and not overlapping any other free
    /// region or live allocation. Used at init and from `dealloc`.
    /// # C: O(N)
    pub unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        // Round addr up to header alignment; round size down accordingly.
        let aligned = align_up(addr, MIN_HOLE_ALIGN);
        let drop = aligned - addr;
        if drop >= size { return; }
        let mut size = size - drop;
        size &= !(MIN_HOLE_ALIGN - 1);
        if size < MIN_HOLE_SIZE { return; }

        let new_ptr = aligned as *mut HoleHdr;
        // SAFETY: add_free_region's caller asserts exclusive ownership of
        // `[aligned, aligned+size)`; the region is unaliased and writable;
        // the cast above makes `new_ptr` the start of that owned region.
        unsafe { new_ptr.write(HoleHdr { size, next: None }) };
        // SAFETY: `new_ptr` was just produced from `aligned`, a non-zero
        // address since `add_free_region`'s caller passed a valid byte
        // range and we returned early on the impossible case.
        let new_nn = unsafe { NonNull::new_unchecked(new_ptr) };

        // Walk the sorted list to find the predecessor.
        let mut prev: *mut HoleHdr = &mut self.first;
        loop {
            // SAFETY: `prev` is initialized to `&mut self.first` and
            // thereafter only advanced through `(*prev).next` pointers
            // that we ourselves inserted; every dereference targets a
            // header we own.
            let next = unsafe { (*prev).next };
            match next {
                Some(n) if n.as_ptr() as usize <= aligned => {
                    prev = n.as_ptr();
                }
                _ => break,
            }
        }

        // SAFETY: `prev` is a list-owned header (sentinel or earlier
        // insert); `new_nn` was just constructed from caller-owned memory.
        // No other reference aliases either node while we hold this list.
        unsafe {
            let next = (*prev).next;
            (*new_nn.as_ptr()).next = next;
            (*prev).next = Some(new_nn);
        }

        // SAFETY: `prev` is a valid list-owned header, freshly linked to
        // the new region above; `try_merge` only walks `next` pointers
        // belonging to this same list.
        unsafe { Self::try_merge(prev) };
    }

    /// If `node` and `node.next` are address-adjacent, fold the
    /// successor into `node`. Repeats while merges succeed.
    /// # SAFETY: `node` is a valid header pointer in this list.
    unsafe fn try_merge(mut node: *mut HoleHdr) {
        loop {
            // SAFETY: caller-asserted; `next` is also a list-owned header
            // by construction.
            let cur = unsafe { &mut *node };
            let Some(nxt_nn) = cur.next else { return; };
            let nxt = nxt_nn.as_ptr();
            let cur_end = (node as usize)
                .saturating_add(cur.size);
            // Skip the sentinel: it has size 0 and is at &self.first;
            // can never abut a real region.
            if cur.size == 0 {
                node = nxt;
                continue;
            }
            if cur_end == nxt as usize {
                // SAFETY: `nxt` came from `cur.next`, a list-owned header
                // pointer that the outer `try_merge` contract guarantees
                // is exclusively reachable through our list mutations.
                let nxt_ref = unsafe { &*nxt };
                cur.size += nxt_ref.size;
                cur.next = nxt_ref.next;
                // Don't advance — re-check the new successor.
                continue;
            }
            node = nxt;
        }
    }

    /// First-fit allocation. Returns `None` on OOM.
    /// # C: O(N)
    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let (need, align) = normalize(layout);

        let mut prev: *mut HoleHdr = &mut self.first;
        loop {
            // SAFETY: list invariant — `prev` is always a valid header;
            // `prev.next` is `Some(NonNull)` into our owned heap or `None`.
            let cur_nn = unsafe { (*prev).next };
            let Some(cur_nn) = cur_nn else { return None; };
            let cur_ptr = cur_nn.as_ptr();
            // SAFETY: list invariant — every `next`-reachable pointer is
            // a valid header inside the heap region the user passed at
            // init, exclusively owned through this list.
            let cur_size = unsafe { (*cur_ptr).size };
            let cur_addr = cur_ptr as usize;

            // Try to carve `[user_start, user_start + need)` out of this hole.
            let mut user_start = align_up(cur_addr, align);
            // If the front padding is > 0 but < MIN_HOLE_SIZE, advance
            // user_start so the front padding becomes a valid hole.
            let front_pad = user_start - cur_addr;
            if front_pad > 0 && front_pad < MIN_HOLE_SIZE {
                user_start = align_up(cur_addr + MIN_HOLE_SIZE, align);
            }
            let front_pad = user_start - cur_addr;
            let user_end = user_start.checked_add(need)?;
            let cur_end  = cur_addr + cur_size;

            if user_end > cur_end {
                // Doesn't fit; advance.
                prev = cur_ptr;
                continue;
            }

            let back_pad = cur_end - user_end;
            // Splice out cur, reinsert front/back fragments as new holes.
            // SAFETY: list invariant; we're only mutating headers we own.
            unsafe {
                (*prev).next = (*cur_ptr).next;
            }

            if front_pad >= MIN_HOLE_SIZE {
                // SAFETY: front padding region is within the formerly-free
                // hole; safe to construct a fresh header.
                unsafe { self.add_free_region(cur_addr, front_pad) };
            }
            if back_pad >= MIN_HOLE_SIZE {
                // SAFETY: back padding region is also within the former hole.
                unsafe { self.add_free_region(user_end, back_pad) };
            }
            // Front padding < MIN_HOLE_SIZE was avoided by re-aligning;
            // back padding < MIN_HOLE_SIZE is leaked (bounded waste, see
            // module docs).

            return NonNull::new(user_start as *mut u8);
        }
    }

    /// Release `[ptr, ptr + need)` (where `need = normalize(layout).0`)
    /// back to the free list, coalescing with neighbors if abutting.
    /// # SAFETY: `ptr` was returned by a prior `alloc(layout)`; the
    /// memory is no longer borrowed.
    /// # C: O(N)
    pub unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let (need, _align) = normalize(layout);
        // SAFETY: caller-asserted; we route to add_free_region which
        // re-validates alignment and minimum size.
        unsafe { self.add_free_region(ptr.as_ptr() as usize, need) };
    }
}

/// Normalize a `Layout` to the allocator's internal block geometry.
/// Returns `(size_padded_up_to_min_hole_align, align_at_least_min_hole_align)`.
/// Same fn called on alloc + dealloc to ensure both sides agree.
/// # C: O(1)
#[inline]
pub fn normalize(layout: Layout) -> (usize, usize) {
    let need = max(align_up(layout.size(), MIN_HOLE_ALIGN), MIN_HOLE_SIZE);
    let align = max(layout.align(), MIN_HOLE_ALIGN);
    (need, align)
}
