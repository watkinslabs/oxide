pub(super) use alloc::sync::Arc;
pub(super) use core::cell::RefCell;
pub(super) use std::collections::{HashMap, HashSet};
pub(super) use std::thread_local;
pub(super) use std::vec::Vec;

pub(super) use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

pub(super) use crate::address_space::AddressSpace;
pub(super) use crate::anon_vma::AnonVma;
pub(super) use crate::vma::{FaultAccess, FaultKind, FileBacking, FileBackingError, SharedFrame, VmaBacking, VmaFlags, VmaProt};

pub(super) const PAGE: u64 = 0x1000;

thread_local! {
    /// root_pa -> (va -> (pa, flags)). One leaf map per address space.
    pub(super) static ROOTS: RefCell<HashMap<u64, HashMap<u64, (u64, u64)>>> = RefCell::new(HashMap::new());
    /// The "active CR3": which root map/translate operate on.
    pub(super) static ACTIVE: RefCell<u64> = RefCell::new(0);
    /// pa -> struct-page refcount (the thing pmm tracks). Only inc/dec/alloc
    /// touch this — map/unmap NEVER do, exactly like the real kernel.
    pub(super) static RC: RefCell<HashMap<u64, i64>> = RefCell::new(HashMap::new());
    /// pa -> mapcount (live user-PTE count; `PageMeta::mapcount`). Mutated by
    /// the SAME closures that move refcount for PTE-boundary events
    /// (alloc=+1, inc_ref=+1, dec_ref=-1), mirroring `setup.rs`. The inode
    /// base hold (shmem) does NOT touch this — a base pin is not a PTE — so
    /// `mapcount` stays exactly equal to the live-PTE count.
    pub(super) static MC: RefCell<HashMap<u64, i64>> = RefCell::new(HashMap::new());
    /// pa -> base holds (inode pin for shmem/memfd frames). Constant per frame.
    pub(super) static BASE: RefCell<HashMap<u64, i64>> = RefCell::new(HashMap::new());
    /// Frames currently on the free list (refcount hit 0). Reuse models the
    /// real allocator handing a freed frame back out.
    pub(super) static POOL: RefCell<Vec<u64>> = RefCell::new(Vec::new());
    /// memfd backing: file_off -> persistent shared frame pa.
    pub(super) static SHFRAMES: RefCell<HashMap<u64, u64>> = RefCell::new(HashMap::new());
    /// A3 model of `PageFlags::ANON_EXCLUSIVE`: an anon frame born from a
    /// fresh fault / COW-copy is exclusive; `inc_ref` (fork-share) clears
    /// it; a dec back to (mapcount==1, refcount==1) restores it. Mirrors
    /// `pmm::setup` exactly so the harness can assert the COW-reuse fast
    /// path only fires when the kernel's `can_reuse_anon_exclusive` would.
    pub(super) static EXCL: RefCell<HashSet<u64>> = RefCell::new(HashSet::new());
    /// A4 rmap model: pa -> the real `Arc<AnonVma>` bound at the fault
    /// (`set_anon_rmap_for_pa`). `check_invariant` walks THIS family's
    /// real chain edges — the self-edge `AddressSpace::mmap` attaches plus
    /// the child edges `fork_cow_pages` attaches — and PTE-checks each
    /// target against `ROOTS`, an rmap-derived mapper count INDEPENDENT of
    /// the mapcount model. Three-way equality (rmap == mapcount == Σ live
    /// PTEs) breaks the self-consistency that let the under-count hide.
    pub(super) static RMAP: RefCell<HashMap<u64, Arc<AnonVma>>> = RefCell::new(HashMap::new());
    /// Recorded invariant violation (first one wins). None = clean.
    pub(super) static BUG: RefCell<Option<std::string::String>> = RefCell::new(None);
}

pub(super) fn reset() {
    ROOTS.with(|r| r.borrow_mut().clear());
    RC.with(|r| r.borrow_mut().clear());
    MC.with(|r| r.borrow_mut().clear());
    BASE.with(|r| r.borrow_mut().clear());
    POOL.with(|r| r.borrow_mut().clear());
    SHFRAMES.with(|r| r.borrow_mut().clear());
    EXCL.with(|r| r.borrow_mut().clear());
    RMAP.with(|r| r.borrow_mut().clear());
    ACTIVE.with(|a| *a.borrow_mut() = 0);
    BUG.with(|b| *b.borrow_mut() = None);
}

pub(super) fn record_bug(s: std::string::String) {
    BUG.with(|b| { if b.borrow().is_none() { *b.borrow_mut() = Some(s); } });
}

pub(super) fn activate(root: u64) { ACTIVE.with(|a| *a.borrow_mut() = root); }

// ---- struct-page refcount primitives (the ONLY mutators of RC) ----

/// Real 4 KiB host frame so the COW copy (hhdm=0 -> identity) touches valid
/// memory. Leaked; the test process is short-lived.
pub(super) fn fresh_pa() -> u64 {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(4096, 4096).unwrap();
    // SAFETY: non-zero 4 KiB layout; alloc_zeroed yields a valid aligned block.
    (unsafe { alloc_zeroed(layout) }) as u64
}

/// Model of `pmm::setup::alloc_one_frame`: prefer a freed frame off the pool,
/// but NEVER hand out one whose refcount is non-zero (the production guard at
/// `setup.rs:339`); set refcount to 1 on success.
pub(super) fn alloc_frame() -> Option<u64> {
    let pa = POOL.with(|p| {
        let mut p = p.borrow_mut();
        // Production guard: skip in-use frames on the free list.
        while let Some(cand) = p.pop() {
            let rc = RC.with(|r| *r.borrow().get(&cand).unwrap_or(&0));
            if rc == 0 { return Some(cand); }
            // rc != 0 -> a frame re-entered the free list while still
            // referenced. Production "consumes and abandons" it (leak-to-mask).
        }
        None
    }).unwrap_or_else(fresh_pa);
    RC.with(|r| { r.borrow_mut().insert(pa, 1); });
    // F157-A1: fresh frame = one pending PTE (matches `setup.rs` alloc mc=1).
    MC.with(|r| { r.borrow_mut().insert(pa, 1); });
    // A3: a recycled frame starts non-exclusive + rmap-clear (mirrors
    // `free_one_frame` clearing ANON_EXCLUSIVE); set_anon_rmap re-marks it.
    EXCL.with(|r| { r.borrow_mut().remove(&pa); });
    RMAP.with(|r| { r.borrow_mut().remove(&pa); });
    Some(pa)
}

pub(super) fn rc_inc(pa: u64) {
    RC.with(|r| { *r.borrow_mut().entry(pa).or_insert(0) += 1; });
    // F157-A1: every inc_ref adds one user PTE (`setup::inc_ref` -> inc_map).
    MC.with(|r| { *r.borrow_mut().entry(pa).or_insert(0) += 1; });
    // A3 (load-bearing clear): a second reference now exists → no longer
    // exclusively owned. Mirrors `pmm::setup::inc_ref`'s clear_flags.
    EXCL.with(|r| { r.borrow_mut().remove(&pa); });
}

/// Model of `pmm::setup::dec_and_maybe_free_frame`: drop one ref; on 0 the
/// frame returns to the free list (reusable). F157-A1: also drops one
/// mapcount (a PTE is being torn down), mirroring `dec_map` then `dec_ref`.
pub(super) fn rc_dec(pa: u64) {
    let mnew = MC.with(|r| {
        let mut m = r.borrow_mut();
        let e = m.entry(pa).or_insert(0);
        *e -= 1;
        *e
    });
    if mnew < 0 {
        record_bug(std::format!("MAP-OVER-DEC: pa={:#x} mapcount went to {}", pa, mnew));
    }
    let new = RC.with(|r| {
        let mut m = r.borrow_mut();
        let e = m.entry(pa).or_insert(0);
        *e -= 1;
        *e
    });
    if new < 0 {
        record_bug(std::format!("OVER-DEC: pa={:#x} refcount went to {}", pa, new));
    }
    // A3 (restore): a fork peer's mapping went away; if exactly one PTE and
    // one reference remain on an anon (rmap-tracked) frame, the survivor is
    // exclusive again. Mirrors `dec_and_maybe_free_frame`'s restore arm.
    if mnew == 1 && new == 1 && RMAP.with(|r| r.borrow().contains_key(&pa)) {
        EXCL.with(|r| { r.borrow_mut().insert(pa); });
    }
    if new == 0 {
        // A3/A4: frame returns to the pool — clear its page-class + rmap
        // state (mirrors free_one_frame + clear_anon_rmap_for_pa).
        EXCL.with(|r| { r.borrow_mut().remove(&pa); });
        RMAP.with(|r| { r.borrow_mut().remove(&pa); });
        POOL.with(|p| p.borrow_mut().push(pa));
    }
}

pub(super) fn rc_get(pa: u64) -> u32 {
    RC.with(|r| (*r.borrow().get(&pa).unwrap_or(&0)).max(0) as u32)
}

// ---- multi-AS page-table model. map/unmap NEVER touch RC. ----

pub(super) struct MultiMmu;
impl MmuOps for MultiMmu {
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, _s: PageSize) -> Option<Pa> {
        let root = ACTIVE.with(|a| *a.borrow());
        // F157-A1: the real per-arch `map` tears down a present leaf at the
        // same VA and RETURNS the displaced PA (different frame) so the mm
        // layer can dec_ref it. Modelling that here — instead of the old
        // silent `insert` that hid map-over-present — is what surfaces the
        // RANK-1 displaced-frame accounting to `check_invariant`.
        ROOTS.with(|r| {
            let prev = r.borrow_mut().entry(root).or_default().insert(va.0, (pa.0, flags.bits()));
            prev.filter(|(old, _)| (old >> 12) != (pa.0 >> 12)).map(|(old, _)| Pa(old))
        })
    }
    unsafe fn unmap(va: Va, _s: PageSize) {
        let root = ACTIVE.with(|a| *a.borrow());
        ROOTS.with(|r| { if let Some(m) = r.borrow_mut().get_mut(&root) { m.remove(&va.0); } });
    }
    fn translate(va: Va) -> Option<(Pa, PageFlags)> {
        let root = ACTIVE.with(|a| *a.borrow());
        ROOTS.with(|r| r.borrow().get(&root).and_then(|m| m.get(&va.0))
            .map(|(pa, f)| (Pa(*pa), PageFlags::from_bits_truncate(*f))))
    }
    unsafe fn flush_va(_va: Va) {}
    fn flush_all_local() {}
    unsafe fn map_at(root_pa: u64, va: Va, pa: Pa, flags: PageFlags, _s: PageSize) -> Option<Pa> {
        ROOTS.with(|r| {
            let prev = r.borrow_mut().entry(root_pa).or_default().insert(va.0, (pa.0, flags.bits()));
            prev.filter(|(old, _)| (old >> 12) != (pa.0 >> 12)).map(|(old, _)| Pa(old))
        })
    }
    unsafe fn activate(root_pa: u64) { activate(root_pa); }
}

// ---- shmem (memfd) file backing with persistent shared frames ----

pub(super) struct MemfdBacking;
impl FileBacking for MemfdBacking {
    fn read_at(&self, _off: u64, dst: &mut [u8]) -> Result<usize, FileBackingError> {
        for b in dst.iter_mut() { *b = 0; }
        Ok(dst.len())
    }
    fn size_hint(&self) -> u64 { 1 << 30 }
    fn ino(&self) -> u64 { 0x6d65_6d66_6400 }
    fn shared_frame(&self, off: u64) -> Result<Option<SharedFrame>, FileBackingError> {
        let off = off & !(PAGE - 1);
        let pa = SHFRAMES.with(|s| {
            if let Some(p) = s.borrow().get(&off) { return *p; }
            let p = fresh_pa();
            s.borrow_mut().insert(off, p);
            // Inode allocates the frame with one base hold (tmpfs.rs:65).
            RC.with(|r| { r.borrow_mut().insert(p, 1); });
            BASE.with(|b| { b.borrow_mut().insert(p, 1); });
            p
        });
        Ok(Some(SharedFrame { pa, map_ref_held: false }))
    }
}

/// Private-file backing (no shared_frame; MAP_PRIVATE COW snapshot).
pub(super) struct PrivFileBacking;
impl FileBacking for PrivFileBacking {
    fn read_at(&self, _off: u64, dst: &mut [u8]) -> Result<usize, FileBackingError> {
        for b in dst.iter_mut() { *b = 0; }
        Ok(dst.len())
    }
    fn size_hint(&self) -> u64 { 1 << 30 }
}

// ---- the global invariant ----

/// After every op: refcount(pa) == live-PTE-count(pa) + base(pa) for every
/// frame, and no live PTE references a freed (pooled, refcount-0) frame.
pub(super) fn check_invariant(label: &str) {
    // Tally live PTEs across all roots.
    let mut live: HashMap<u64, i64> = HashMap::new();
    // (root, pa) -> the VAs in that AS mapping pa. Built once here so the
    // rmap walk (5) is O(edges) not O(edges·leaves).
    let mut by_rp: HashMap<(u64, u64), Vec<u64>> = HashMap::new();
    let freed: HashSet<u64> = POOL.with(|p| p.borrow().iter().copied().collect());
    ROOTS.with(|roots| {
        for (root, leaves) in roots.borrow().iter() {
            for (va, (pa, _)) in leaves.iter() {
                let pa = *pa & !(PAGE - 1);
                *live.entry(pa).or_insert(0) += 1;
                by_rp.entry((*root, pa)).or_default().push(*va);
                // (1) free-while-mapped: a live PTE points at a pooled frame.
                let rc = RC.with(|r| *r.borrow().get(&pa).unwrap_or(&0));
                if rc <= 0 || freed.contains(&pa) {
                    record_bug(std::format!(
                        "[{}] FREE-WHILE-MAPPED: root={:#x} va={:#x} -> pa={:#x} refcount={}",
                        label, root, va, pa, rc));
                }
            }
        }
    });
    // (2) refcount == live + base for every frame that has any live PTE.
    for (pa, cnt) in live.iter() {
        let base = BASE.with(|b| *b.borrow().get(pa).unwrap_or(&0));
        let rc = RC.with(|r| *r.borrow().get(pa).unwrap_or(&0));
        let expect = cnt + base;
        if rc != expect {
            let dir = if rc < expect { "UNDER-COUNT" } else { "over-count" };
            record_bug(std::format!(
                "[{}] {}: pa={:#x} refcount={} but live_ptes={} + base={} = {}",
                label, dir, pa, rc, cnt, base, expect));
        }
        // (3) F157-A1: mapcount == live-PTE count, EXACTLY (both directions).
        // A frame displaced by a map-over-present install whose mapcount was
        // NOT decremented shows here as mapcount > live_ptes; a double-dec
        // (e.g. COW arm decrementing both the manual `cur` AND the displaced
        // return) shows as mapcount < live_ptes.
        let mc = MC.with(|m| *m.borrow().get(pa).unwrap_or(&0));
        if mc != *cnt {
            let dir = if mc < *cnt { "MAPCOUNT-UNDER" } else { "MAPCOUNT-OVER" };
            record_bug(std::format!(
                "[{}] {}: pa={:#x} mapcount={} but live_ptes={}",
                label, dir, pa, mc, cnt));
        }
    }
    // (4) F157-A1: a frame with NO live PTE must have mapcount 0 (a leaked
    // displaced frame would sit at mapcount>0 with zero mappings). Scan every
    // frame the mapcount model knows about that isn't in `live`.
    MC.with(|m| {
        for (pa, mc) in m.borrow().iter() {
            if *mc != 0 && !live.contains_key(pa) {
                record_bug(std::format!(
                    "[{}] MAPCOUNT-LEAK: pa={:#x} mapcount={} but 0 live PTEs",
                    label, pa, mc));
            }
        }
    });
    // (5) A4 STRONG rmap invariant: rmap-walk count == mapcount == Σ live
    // PTEs, three INDEPENDENTLY-derived numbers. For each anon frame, walk
    // its REAL `AnonVma` chain (the self-edge `mmap` attaches + the child
    // edges `fork_cow_pages` attaches) and PTE-check each candidate
    // against `ROOTS`. This is the tier the old harness lacked: the prior
    // checks compared the mapcount MODEL against ROOTS, but both moved in
    // lock-step so a path that under-edged the rmap was invisible. Walking
    // the actual chain surfaces a missing self-edge (GAP A4-1): a
    // never-forked page is mapped (live_pte=1, mapcount=1) yet the chain
    // yields 0 → FAIL until `mmap` attaches the owning edge.
    RMAP.with(|rm| {
        for (pa, av) in rm.borrow().iter() {
            let live_ct = *live.get(pa).unwrap_or(&0);
            if live_ct == 0 { continue; } // freed/unmapped anon frame
            let mut rmap_ct: i64 = 0;
            av.walk(|mm, start, end| {
                let root = mm.root_pa();
                if let Some(vas) = by_rp.get(&(root, *pa)) {
                    for va in vas {
                        if *va >= start && *va < end { rmap_ct += 1; }
                    }
                }
            });
            let mc = MC.with(|m| *m.borrow().get(pa).unwrap_or(&0));
            if rmap_ct != live_ct || rmap_ct != mc {
                record_bug(std::format!(
                    "[{}] RMAP-MISMATCH: pa={:#x} rmap_walk={} but live_ptes={} mapcount={}",
                    label, pa, rmap_ct, live_ct, mc));
            }
        }
    });
}
