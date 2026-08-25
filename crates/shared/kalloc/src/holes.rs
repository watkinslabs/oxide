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

mod region_index;
mod mutate;
mod allocate;

/// Rejection reason for a free-list mutation that would violate ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoleListError {
    /// Region arithmetic overflowed the machine address space.
    AddressOverflow,
    /// A linked node cannot describe a valid, strictly ordered free region.
    MalformedNode,
    /// The requested free region intersects a region already owned by the list.
    OverlappingFree,
    /// A free-list node lies outside allocator-owned backing memory.
    OutsideOwnedRegion,
}

impl HoleListError {
    /// Stable diagnostic tag for allocator integrity failures. # C: O(1)
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::AddressOverflow => b"address-overflow",
            Self::MalformedNode => b"malformed-node",
            Self::OverlappingFree => b"overlapping-free",
            Self::OutsideOwnedRegion => b"outside-owned-region",
        }
    }
}

/// Each free region begins with this header. `size` is the region's
/// total byte length including the header itself.
#[repr(C)]
pub struct HoleHdr {
    pub size: usize,
    pub next: Option<NonNull<HoleHdr>>,
}

/// Permanent metadata for one allocator-owned backing region. This prefix is
/// never returned to callers, so free-list corruption cannot alter it.
#[repr(C)]
struct RegionHdr {
    end: usize,
    next: Option<NonNull<RegionHdr>>,
    left: Option<NonNull<RegionHdr>>,
    right: Option<NonNull<RegionHdr>>,
    height: u8,
}

/// Minimum size of a free region (must hold at least the header).
pub const MIN_HOLE_SIZE: usize = mem::size_of::<HoleHdr>();
/// Minimum alignment of a free region's start.
pub const MIN_HOLE_ALIGN: usize = mem::align_of::<HoleHdr>();
/// Reserved prefix for one backing-region descriptor, rounded for hole starts.
const REGION_HEADER_SIZE: usize = (mem::size_of::<RegionHdr>() + MIN_HOLE_ALIGN - 1) & !(MIN_HOLE_ALIGN - 1);

/// Round `addr` up to the next multiple of `align`. `align` must be a
/// power of two.
#[inline]
fn align_up(addr: usize, align: usize) -> Option<usize> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// Ring depth for `EvictHistory`. Diagnostic-only (`debug-heappoison`).
#[cfg(feature = "debug-heappoison")]
const EVICT_HISTORY_SLOTS: usize = 4096;

#[cfg(feature = "debug-heappoison")]
#[derive(Clone, Copy)]
struct EvictedSlot { base: usize, size: u32, free_ip: u64 }
#[cfg(feature = "debug-heappoison")]
impl EvictedSlot { const EMPTY: EvictedSlot = EvictedSlot { base: 0, size: 0, free_ip: crate::caller::UNKNOWN_RETURN_IP }; }

/// Records (base, size, free_ip) for blocks that have LEFT the quarantine
/// ring (`poison::Quar`) and rejoined this real hole list. Quarantine's own
/// `lookup`/`scan_window` only see blocks still quarantined; once evicted, a
/// corruption discovered later (a real hole's header found broken, possibly
/// long after the corrupting write) has no provenance at all otherwise.
/// Lives directly on `HoleList` (not `Quar`) so `try_merge`/`alloc`'s own
/// diagnostic prints can consult it without re-locking the allocator they're
/// already running inside of. Diagnostic-only, never in a shipped profile.
#[cfg(feature = "debug-heappoison")]
struct EvictHistory { slots: [EvictedSlot; EVICT_HISTORY_SLOTS], idx: usize }

#[cfg(feature = "debug-heappoison")]
impl EvictHistory {
    const fn new() -> Self { Self { slots: [EvictedSlot::EMPTY; EVICT_HISTORY_SLOTS], idx: 0 } }

    fn record(&mut self, base: usize, size: u32, free_ip: u64) {
        let i = self.idx;
        self.idx = (i + 1) % EVICT_HISTORY_SLOTS;
        self.slots[i] = EvictedSlot { base, size, free_ip };
    }

    /// Most recent evicted block whose original span contained `addr`, if
    /// still within the ring's retention window. # C: O(EVICT_HISTORY_SLOTS)
    fn lookup(&self, addr: usize) -> Option<(usize, u32, u64)> {
        // Newest-first (idx-1 backward) so a re-freed address reports its
        // MOST RECENT owner, not an earlier one still in the ring.
        for k in 0..EVICT_HISTORY_SLOTS {
            let i = (self.idx + EVICT_HISTORY_SLOTS - 1 - k) % EVICT_HISTORY_SLOTS;
            let s = self.slots[i];
            if s.size != 0 && addr >= s.base && addr < s.base + s.size as usize {
                return Some((s.base, s.size, s.free_ip));
            }
        }
        None
    }
}

/// Sorted singly-linked list of free regions. The list is owned by
/// `HoleList`; `KAlloc` wraps it in a `Spinlock`.
/// B1346 corruption hunt: direct-mapped `base → last dealloc-return-IP` cache.
/// The corrupt free-list node is FREE when detected, so its last free-IP names
/// where the stale-pointer WRITER freed its own object (addr2line → the Drop
/// glue → the writer's type). Diagnostic-only; overwrite-on-collision is fine.
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
const FREE_IP_CAP: usize = 8192;
/// Per-block provenance slot: `(base, cur_alloc_ip, prev_alloc_ip, free_ip)`.
/// `prev_alloc_ip` is the alloc-IP of the allocation BEFORE the current one —
/// the writer's object type when the block was recycled (the current alloc is
/// the recycled victim, e.g. an ArcInner<File>; the previous is what a stale
/// pointer still targets).
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub(crate) struct FreeIpRing { slots: [(usize, u64, u64, u64); FREE_IP_CAP] }
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
impl FreeIpRing {
    const fn new() -> Self { Self { slots: [(0usize, 0u64, 0u64, 0u64); FREE_IP_CAP] } }
    #[inline]
    fn idx(base: usize) -> usize { (base >> 4).wrapping_mul(2654435761) % FREE_IP_CAP }
    /// On alloc: shift cur→prev (only when the same base is re-allocated), set cur, clear free.
    fn record_alloc(&mut self, base: usize, ip: u64) {
        let i = Self::idx(base);
        let prev = if self.slots[i].0 == base { self.slots[i].1 } else { 0 };
        self.slots[i] = (base, ip, prev, 0);
    }
    /// On free: stamp free_ip, keeping the alloc history for this base.
    fn record_free(&mut self, base: usize, ip: u64) {
        let i = Self::idx(base);
        if self.slots[i].0 == base { self.slots[i].3 = ip; }
        else { self.slots[i] = (base, 0, 0, ip); }
    }
    /// `(cur_alloc_ip, prev_alloc_ip, free_ip)` for `base`, if tracked.
    fn lookup(&self, base: usize) -> Option<(u64, u64, u64)> {
        let (b, a, p, f) = self.slots[Self::idx(base)];
        if b == base && (a != 0 || p != 0 || f != 0) { Some((a, p, f)) } else { None }
    }
}

pub struct HoleList {
    /// Sentinel header so all "list head" updates go through `next`,
    /// without a separate `head: Option<...>` case.
    first: HoleHdr,
    /// Region descriptors live in reserved prefixes of their backing ranges.
    /// `regions` retains insertion order for rare diagnostic dumps; ordinary
    /// ownership checks use the balanced address index rooted at `region_root`.
    regions: Option<NonNull<RegionHdr>>,
    region_root: Option<NonNull<RegionHdr>>,
    /// See `EvictHistory`.
    #[cfg(feature = "debug-heappoison")]
    evict_history: EvictHistory,
    /// B1346: free-IP provenance ring (see `FreeIpRing`).
    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
    free_ips: FreeIpRing,
}

// SAFETY: `HoleList` mediates exclusive access to the heap region via
// the outer `Spinlock`; the `NonNull<HoleHdr>` chain only points into
// memory owned by the list, which the user reserves once at init.
unsafe impl Send for HoleList {}

impl HoleList {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            first: HoleHdr { size: 0, next: None },
            regions: None,
            region_root: None,
            #[cfg(feature = "debug-heappoison")]
            evict_history: EvictHistory::new(),
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            free_ips: FreeIpRing::new(),
        }
    }

    /// B1346: record `base`'s alloc-return-IP (shifts the prior one to prev).
    /// # C: O(1)
    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
    pub fn record_alloc_ip(&mut self, base: usize, alloc_ip: u64) {
        self.free_ips.record_alloc(base, alloc_ip);
    }

    /// B1346: record `base`'s dealloc-return-IP just before it rejoins the free
    /// list, so a later corruption of that node can be traced to its last freer.
    /// # C: O(1)
    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
    pub fn record_free_ip(&mut self, base: usize, free_ip: u64) {
        self.free_ips.record_free(base, free_ip);
    }

    /// B1346: print the corrupt node's provenance. `free_ip`→the last freer;
    /// `alloc_ip`→the recycled victim's type; **`prev_alloc_ip`→the WRITER's
    /// object type** (what a stale pointer targeted before recycling).
    /// addr2line each on the kernel ELF. # C: O(1)
    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
    pub(crate) fn print_free_ip(&self, base: usize) {
        if let Some((alloc_ip, prev_alloc_ip, free_ip)) = self.free_ips.lookup(base) {
            klog::write_primary_raw(b"[KALLOC] corrupt-node prov base=");
            klog::write_primary_hex_u64(base as u64);
            klog::write_primary_raw(b" free_ip=0x");
            klog::write_primary_hex_u64(free_ip);
            klog::write_primary_raw(b" alloc_ip=0x");
            klog::write_primary_hex_u64(alloc_ip);
            klog::write_primary_raw(b" prev_alloc_ip=0x");
            klog::write_primary_hex_u64(prev_alloc_ip);
            klog::write_primary_raw(b"\n");
        }
    }

    /// Record that `[base, base+size)` just left quarantine and is about to
    /// be reinserted as a real hole. Call BEFORE the reinsertion so a
    /// corruption discovered on this span later can be traced to its last
    /// known freeing site. # C: O(1)
    #[cfg(feature = "debug-heappoison")]
    pub fn record_evicted(&mut self, base: usize, size: u32, free_ip: u64) {
        self.evict_history.record(base, size, free_ip);
    }

    /// Provenance for `addr`, if it falls within a block this list's owner
    /// evicted from quarantine within the retention window. # C: O(1) amortized
    #[cfg(feature = "debug-heappoison")]
    pub fn lookup_evicted(&self, addr: usize) -> Option<(usize, u32, u64)> {
        self.evict_history.lookup(addr)
    }

    /// Register an allocator-owned backing range and insert its usable suffix.
    /// The descriptor stays outside every allocation for the range lifetime.
    /// # SAFETY: caller exclusively owns the whole range for this allocator.
    /// # C: O(regions + holes)
    pub unsafe fn add_region(&mut self, addr: usize, size: usize) -> Result<(), HoleListError> {
        let aligned = align_up(addr, MIN_HOLE_ALIGN).ok_or(HoleListError::AddressOverflow)?;
        let skipped = aligned - addr;
        if skipped >= size { return Err(HoleListError::MalformedNode); }
        let size = (size - skipped) & !(MIN_HOLE_ALIGN - 1);
        let end = aligned.checked_add(size).ok_or(HoleListError::AddressOverflow)?;
        let usable = aligned.checked_add(REGION_HEADER_SIZE).ok_or(HoleListError::AddressOverflow)?;
        if end.checked_sub(usable).unwrap_or(0) < MIN_HOLE_SIZE { return Err(HoleListError::MalformedNode); }
        let mut region = self.regions;
        while let Some(node) = region {
            // SAFETY: region descriptors occupy reserved prefixes and only this
            // list mutates their links while the outer allocator lock is held.
            let existing = unsafe { node.as_ref() };
            let existing_start = node.as_ptr() as usize;
            if existing_start < end && aligned < existing.end {
                #[cfg(feature = "debug-heappoison")]
                {
                    klog::write_primary_raw(b"[KALLOC] region-collision new=");
                    klog::write_primary_hex_u64(aligned as u64);
                    klog::write_primary_raw(b" new-end=");
                    klog::write_primary_hex_u64(end as u64);
                    klog::write_primary_raw(b" existing=");
                    klog::write_primary_hex_u64(existing_start as u64);
                    klog::write_primary_raw(b" existing-end=");
                    klog::write_primary_hex_u64(existing.end as u64);
                    klog::write_primary_raw(b"\n");
                }
                return Err(HoleListError::OverlappingFree);
            }
            region = existing.next;
        }
        let hdr = aligned as *mut RegionHdr;
        // SAFETY: `aligned` starts the caller-owned range and is never exposed
        // as allocatable storage after this descriptor is installed.
        unsafe {
            hdr.write(RegionHdr {
                end,
                next: self.regions,
                left: None,
                right: None,
                height: 1,
            })
        };
        // SAFETY: `hdr` is aligned and initialized by the preceding write.
        let node = unsafe { NonNull::new_unchecked(hdr) };
        self.regions = Some(node);
        // SAFETY: the overlap pass above proved `node` has a unique address
        // interval; all descriptors are permanent and the caller holds the
        // allocator lock exclusively while the AVL links are mutated.
        self.region_root = Some(unsafe { Self::insert_region(self.region_root, node) });
        // SAFETY: the usable suffix is contained in the freshly registered range.
        let result = unsafe { self.add_free_region(usable, end - usable) };
        #[cfg(feature = "debug-heappoison")]
        if result.is_err() {
            klog::write_primary_raw(b"[KALLOC] seq=");
            klog::write_primary_dec_u64(crate::hooks::next_seq());
            klog::write_primary_raw(b" add-region-failed start=");
            klog::write_primary_hex_u64(aligned as u64);
            klog::write_primary_raw(b" usable=");
            klog::write_primary_hex_u64(usable as u64);
            klog::write_primary_raw(b" end=");
            klog::write_primary_hex_u64(end as u64);
            klog::write_primary_raw(b"\n");
        }
        result
    }

    /// True when `[start, end)` is allocatable storage in one registered
    /// region. Linux uses address-indexed VM/slab ownership metadata rather
    /// than rescanning every arena on each allocator operation.
    /// # C: O(log regions)
    fn owns_range(&self, start: usize, end: usize) -> bool {
        if start >= end { return false; }
        let mut region = self.region_root;
        while let Some(node) = region {
            // SAFETY: descriptors are in permanently reserved backing prefixes,
            // never in a free block or a caller-visible allocation.
            let current = unsafe { node.as_ref() };
            let base = node.as_ptr() as usize;
            if start < base {
                region = current.left;
            } else if start >= current.end {
                region = current.right;
            } else {
                return base.checked_add(REGION_HEADER_SIZE)
                    .is_some_and(|usable| start >= usable && end <= current.end);
            }
        }
        false
    }

    /// Test-only height of the production ownership index. # C: O(1)
    #[cfg(test)]
    pub(crate) fn region_tree_height(&self) -> u8 { Self::region_height(self.region_root) }

    /// Validate a readable free-list header without trusting in-band links.
    /// # C: O(log regions)
    fn owns_header(&self, addr: usize) -> bool {
        addr % MIN_HOLE_ALIGN == 0
            && addr.checked_add(MIN_HOLE_SIZE).is_some_and(|end| self.owns_range(addr, end))
    }

    /// Walk the whole free list and reject the first node that violates a
    /// live invariant: owned/aligned header, minimum size, sorted address
    /// order, and non-overlap with its successor. Diagnostic-only bisection
    /// tool (debug-heappoison) for locating WHEN corruption first appears,
    /// as opposed to the reactive asserts in `alloc`/`add_free_region` that
    /// only fire when a corrupted node is finally carved. Returns the
    /// address of the first bad node, or `None` if the list is intact.
    /// # C: O(N)
    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
    pub fn validate(&self) -> Option<usize> {
        let mut prev_end: Option<usize> = None;
        let mut cur = self.first.next;
        while let Some(node) = cur {
            let addr = node.as_ptr() as usize;
            if !self.owns_header(addr) { return Some(addr); }
            // SAFETY: `owns_header` just confirmed `addr` is a readable,
            // allocator-owned, aligned header-sized range.
            let hdr = unsafe { node.as_ref() };
            // B1347: match the carve's own gate (holes.rs:762) — size must be
            // >= MIN, MIN_HOLE_ALIGN-multiple, and the WHOLE span owned. Without
            // the align + owns_range checks a node whose corrupted `size` extends
            // just past its region-end (no u64 overflow) passes validate() yet
            // trips the carve's listed-free-outside — the exact blind spot that
            // let the zram-disksize corruption slip past diag-validate.
            if hdr.size < MIN_HOLE_SIZE || hdr.size % MIN_HOLE_ALIGN != 0 { return Some(addr); }
            let Some(end) = addr.checked_add(hdr.size) else { return Some(addr); };
            if !self.owns_range(addr, end) { return Some(addr); }
            if prev_end.is_some_and(|p| addr < p) { return Some(addr); }
            prev_end = Some(end);
            cur = hdr.next;
        }
        None
    }

    /// Visit every free-list node's `(addr, size)` in address order. Stops
    /// at list end or the first node that fails `owns_header` (silently —
    /// callers that need corruption detail should use `validate`/`dump`).
    /// Test-only: lets a hosted fuzz harness cross-check free-list addresses
    /// against the quarantine ring without `alloc` (this crate has none).
    /// # C: O(N)
    #[cfg(any(test, feature = "hosted"))]
    pub(crate) fn for_each_free(&self, mut f: impl FnMut(usize, usize)) {
        let mut cur = self.first.next;
        loop {
            let Some(node) = cur else { break };
            let addr = node.as_ptr() as usize;
            if !self.owns_header(addr) { break; }
            // SAFETY: `owns_header` just confirmed a readable, owned, aligned header.
            let hdr = unsafe { node.as_ref() };
            if hdr.size < MIN_HOLE_SIZE { break; }
            f(addr, hdr.size);
            cur = hdr.next;
        }
    }

    /// Print every free-list node's (addr, size) up to `cap` entries, then
    /// stop (either at list end or the first node that fails `owns_header`,
    /// printed distinctly so the corrupt node's exact neighbors in address
    /// order are visible). Diagnostic-only (debug-heappoison): names the
    /// allocation immediately adjacent to a corrupted node, which a bare
    /// `validate()` bad-address report cannot show. # C: O(min(N, cap))
    #[cfg(feature = "debug-heappoison")]
    pub fn dump(&self, cap: usize) {
        klog::write_primary_raw(b"[KALLOC-DUMP] begin\n");
        let mut cur = self.first.next;
        let mut n = 0usize;
        while let Some(node) = cur {
            if n >= cap { klog::write_primary_raw(b"[KALLOC-DUMP] truncated\n"); break; }
            let addr = node.as_ptr() as usize;
            if !self.owns_header(addr) {
                klog::write_primary_raw(b"[KALLOC-DUMP] BAD addr=");
                klog::write_primary_hex_u64(addr as u64);
                klog::write_primary_raw(b"\n");
                break;
            }
            // SAFETY: `owns_header` just confirmed a readable, owned, aligned header.
            let hdr = unsafe { node.as_ref() };
            klog::write_primary_raw(b"[KALLOC-DUMP] addr=");
            klog::write_primary_hex_u64(addr as u64);
            klog::write_primary_raw(b" size=");
            klog::write_primary_dec_u64(hdr.size as u64);
            klog::write_primary_raw(b"\n");
            if hdr.size < MIN_HOLE_SIZE { break; }
            cur = hdr.next;
            n += 1;
        }
        klog::write_primary_raw(b"[KALLOC-DUMP] end\n");
    }

    /// Live free-hole count. Diagnostic companion to `walkstat`: the walk-step
    /// averages are only interpretable against the list length that produced
    /// them. # C: O(N)
    #[cfg(feature = "debug-heapwalk")]
    pub fn hole_count(&self) -> u64 {
        let mut n = 0u64;
        let mut cur = self.first.next;
        while let Some(node) = cur {
            if !self.owns_header(node.as_ptr() as usize) { break; }
            // SAFETY: list invariant — every `next`-reachable header lies in a
            // region this list owns, and the caller holds the allocator lock.
            let hdr = unsafe { node.as_ref() };
            if hdr.size < MIN_HOLE_SIZE { break; }
            cur = hdr.next;
            n += 1;
        }
        n
    }


}

/// Normalize a `Layout` to the allocator's internal block geometry.
/// Returns `(size_padded_up_to_min_hole_align, align_at_least_min_hole_align)`.
/// Same fn called on alloc + dealloc to ensure both sides agree.
/// # C: O(1)
#[inline]
pub fn normalize(layout: Layout) -> Option<(usize, usize)> {
    let need = max(align_up(layout.size(), MIN_HOLE_ALIGN)?, MIN_HOLE_SIZE);
    let align = max(layout.align(), MIN_HOLE_ALIGN);
    Some((need, align))
}
