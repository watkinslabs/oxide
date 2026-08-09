// The relocation machinery, checked against a page supply and a page-table
// tree the test owns.
//
// The jump cannot be tested — it does not return — so everything up to it is
// tested here instead: the identity tables actually translate the addresses
// the trampoline will touch, and the walk the trampoline performs produces the
// copies the staging built the chain for.
//
// The page-table tree is built by the kernel's OWN walker driver
// (`hal::pt_walker`) over a test `PtWalker` whose bit encoding this file
// states. That scope is deliberate and it is a real limit: this proves the
// builder walks, allocates and links tables correctly, and it does NOT prove
// the architecture's leaf bits are right — those are the arch walker's, and
// they cannot be exercised hosted because their TLB primitives are privileged.

extern crate alloc;
use alloc::vec::Vec;

use hal::pt_walker::{MigrationEntry, PteMarker, PtWalker, SwapEntry};
use hal::PageFlags;

use crate::frames::Frames;
use crate::image::KImage;
use crate::machine::{idmap, plan, walk};
use crate::uapi::{ImageType, KexecSegment, PAGE_SIZE};

use super::fake::{FakeFrames, PatternSource};
use super::gate::test_lock;

// --- a page supply over one contiguous host arena ---------------------------

/// Physical memory the test owns outright: one contiguous host allocation,
/// addressed as if it started at `BASE_PA`.
///
/// Contiguity is the point. The walker reaches a table page as `hhdm + pa`, so
/// a supply whose pages are separate allocations has no single offset that
/// could serve as an HHDM and cannot host a page-table tree at all.
const BASE_PA: u64 = 0x1000_0000;
const ARENA_PAGES: usize = 512;

struct Arena {
    mem: Vec<u8>,
    next: usize,
}

impl Arena {
    fn new() -> Self {
        // One extra page of slack so the base can be rounded up to a page
        // boundary without running off the end.
        Self { mem: alloc::vec![0u8; (ARENA_PAGES + 1) * PAGE_SIZE as usize], next: 0 }
    }
    fn origin(&self) -> u64 {
        let raw = self.mem.as_ptr() as u64;
        (raw + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }
    /// Offset added to a physical address to reach the host mapping of it.
    fn hhdm(&self) -> u64 { self.origin().wrapping_sub(BASE_PA) }
    fn alloc(&mut self) -> Option<u64> {
        if self.next >= ARENA_PAGES { return None; }
        let pa = BASE_PA + self.next as u64 * PAGE_SIZE;
        self.next += 1;
        // SAFETY: `pa` is the `next`-th page of an arena of ARENA_PAGES + 1
        // pages, so the whole page lies inside the allocation.
        unsafe { core::ptr::write_bytes((self.hhdm() + pa) as *mut u8, 0, PAGE_SIZE as usize) };
        Some(pa)
    }
    fn read(&self, pa: u64) -> u64 {
        // SAFETY: every address this is called with came from `alloc` or from
        // a table entry the builder wrote, both inside the arena.
        unsafe { ((self.hhdm() + pa) as *const u64).read() }
    }
}

// --- a walker whose bit encoding the test states ---------------------------

const P: u64 = 1 << 0;
const W: u64 = 1 << 1;
const BLOCK: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const ADDR: u64 = 0x000f_ffff_ffff_f000;

struct TestWalker;

impl PtWalker for TestWalker {
    const PHYS_MASK: u64 = ADDR;
    unsafe fn read_pt_base(_va: u64) -> u64 { 0 }
    unsafe fn flush_va(_va: u64) {}
    fn is_valid(e: u64) -> bool { e & P != 0 }
    fn is_huge_or_block(e: u64) -> bool { e & P != 0 && e & BLOCK != 0 }
    fn pack_table(child: u64) -> u64 { (child & ADDR) | P | W }
    fn pack_device_leaf(pa: u64) -> u64 { (pa & ADDR) | P | W | NX }
    fn pack_4k_leaf(pa: u64, f: PageFlags) -> u64 {
        let mut e = (pa & ADDR) | P;
        if f.contains(PageFlags::WRITE) { e |= W; }
        if !f.contains(PageFlags::EXEC) { e |= NX; }
        e
    }
    fn pack_block_leaf(pa: u64, f: PageFlags) -> u64 { Self::pack_4k_leaf(pa, f) | BLOCK }
    fn pack_swap_entry(_e: SwapEntry) -> u64 { 0 }
    fn unpack_swap_entry(_r: u64) -> Option<SwapEntry> { None }
    fn pack_migration_entry(_e: MigrationEntry) -> u64 { 0 }
    fn unpack_migration_entry(_r: u64) -> Option<MigrationEntry> { None }
    fn leaf_wrprotect(r: u64) -> u64 { r & !W }
    fn leaf_set_uffd_wp(r: u64) -> u64 { r }
    fn leaf_clear_uffd_wp(r: u64) -> u64 { r }
    fn leaf_is_uffd_wp(_r: u64) -> bool { false }
    fn nonpresent_set_uffd_wp(r: u64) -> u64 { r }
    fn nonpresent_clear_uffd_wp(r: u64) -> u64 { r }
    fn nonpresent_is_uffd_wp(_r: u64) -> bool { false }
    fn can_split_kernel_leaf() -> bool { true }
    fn split_child_leaf(b: u64, pa: u64, level: u8) -> u64 {
        let keep = b & !ADDR & !BLOCK;
        if level == 3 { (pa & ADDR) | keep } else { (pa & ADDR) | keep | BLOCK }
    }
    fn publish_table_barrier() {}
    fn leaf_set_present(r: u64, present: bool) -> u64 { if present { r | P } else { r & !P } }
    fn pack_pte_marker(_m: PteMarker) -> u64 { 0 }
    fn unpack_pte_marker(_r: u64) -> Option<PteMarker> { None }
}

/// Resolve `va` through the tree at `root`, independently of the builder:
/// descend until a block or bottom-level leaf, then add the offset.
fn translate(a: &Arena, root: u64, va: u64) -> Option<u64> {
    let shifts = [39u32, 30, 21, 12];
    let mut table = root;
    for (level, sh) in shifts.iter().enumerate() {
        let e = a.read(table + 8 * ((va >> sh) & 0x1ff));
        if e & P == 0 { return None; }
        if level == 3 { return Some((e & ADDR) | (va & (PAGE_SIZE - 1))); }
        if e & BLOCK != 0 {
            let span = 1u64 << sh;
            return Some((e & ADDR & !(span - 1)) | (va & (span - 1)));
        }
        table = e & ADDR;
    }
    None
}

fn build(a: &mut Arena, ranges: &[(u64, u64)]) -> u64 {
    let root = a.alloc().expect("root");
    let hhdm = a.hhdm();
    let mut pages: Vec<u64> = Vec::new();
    for _ in 0..plan::table_pages(ranges) { pages.push(a.alloc().expect("table")); }
    let mut take = || pages.pop();
    // SAFETY: every page came from the arena, is zeroed, and `hhdm` maps all
    // of it; the tree is owned by this test alone.
    unsafe { idmap::build::<TestWalker, _>(root, ranges, hhdm, &mut take).expect("build") };
    root
}

#[test]
fn the_identity_map_translates_every_address_it_covers() {
    let mut a = Arena::new();
    let ranges = plan::normalize(&[(0x4000_0000, 0x4040_0000)]);
    let root = build(&mut a, &ranges);
    for va in [0x4000_0000u64, 0x4000_1000, 0x401f_ffff, 0x4020_0000, 0x403f_ffff] {
        assert_eq!(translate(&a, root, va), Some(va), "identity broken at {va:#x}");
    }
    // And nothing outside it: a map that translated addresses it was never
    // asked to cover would hide a missing range rather than fault on it.
    assert_eq!(translate(&a, root, 0x4040_0000), None);
    assert_eq!(translate(&a, root, 0x8000_0000), None);
}

#[test]
fn a_range_that_starts_mid_block_is_still_reachable_from_its_first_byte() {
    // The alignment case the trampoline actually meets: a segment destination
    // is page aligned, not 2 MiB aligned. If the plan rounded the start UP,
    // the first page of the segment would be unmapped and the very first copy
    // would fault with nothing left able to report it.
    let mut a = Arena::new();
    let start = 0x4000_0000 + PAGE_SIZE;
    let ranges = plan::normalize(&[(start, start + PAGE_SIZE)]);
    let root = build(&mut a, &ranges);
    assert_eq!(translate(&a, root, start), Some(start));
    assert_eq!(translate(&a, root, 0x4000_0000), Some(0x4000_0000));
}

#[test]
fn the_transition_mapping_reaches_the_control_page_at_its_kernel_address() {
    // Without this leaf the instruction after the trampoline's `mov cr3` is
    // unmapped, and the kernel is already dismantled by then.
    let mut a = Arena::new();
    let ranges = plan::normalize(&[(0x4000_0000, 0x4020_0000)]);
    let root = build(&mut a, &ranges);
    let control = 0x4001_0000u64;
    let kva = 0xffff_8000_0000_0000u64 + control;
    let mut pages: Vec<u64> = Vec::new();
    for _ in 0..plan::TRANSITION_TABLE_PAGES { pages.push(a.alloc().expect("table")); }
    let hhdm = a.hhdm();
    let mut take = || pages.pop();
    // SAFETY: arena-owned zeroed pages, `hhdm` maps the whole tree.
    unsafe { idmap::map_transition::<TestWalker, _>(root, kva, control, hhdm, &mut take).unwrap() };
    assert_eq!(translate(&a, root, kva), Some(control));
    // The identity leaf for the same page is untouched.
    assert_eq!(translate(&a, root, control), Some(control));
}

#[test]
fn table_pages_is_exactly_what_the_build_consumes() {
    // Under-count and the build fails mid-tree; over-count and the image parks
    // control pages it never uses for its whole life.
    for ranges in [alloc::vec![(0x4000_0000u64, 0x4020_0000u64)],
                   alloc::vec![(0u64, 0x4000_0000u64)],
                   alloc::vec![(0x4000_0000u64, 0x4020_0000u64),
                               (0x1_0000_0000u64, 0x1_0020_0000u64)]] {
        let mut a = Arena::new();
        let root = a.alloc().unwrap();
        let want = plan::table_pages(&ranges);
        let mut pages: Vec<u64> = Vec::new();
        for _ in 0..want - 1 { pages.push(a.alloc().unwrap()); }
        let hhdm = a.hhdm();
        let used = core::cell::Cell::new(0u64);
        let mut take = || { let p = pages.pop(); if p.is_some() { used.set(used.get() + 1); } p };
        // SAFETY: arena-owned zeroed pages; `hhdm` maps the whole tree.
        unsafe { idmap::build::<TestWalker, _>(root, &ranges, hhdm, &mut take).expect("build") };
        assert_eq!(used.get() + 1, want, "table_pages disagrees with the build");
    }
}

// --- the walk the trampoline performs ---------------------------------------

fn seg(mem: u64, memsz: u64) -> KexecSegment {
    KexecSegment { buf: 0, bufsz: memsz, mem, memsz }
}

#[test]
fn the_walk_reproduces_the_staged_chain_page_for_page() {
    let _g = test_lock();
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(4 * PAGE_SIZE as usize);
    let segs = alloc::vec![seg(0x20_0000, 3 * PAGE_SIZE), seg(0x60_0000, PAGE_SIZE)];
    let mut img = KImage::new(0x20_0000, ImageType::Default, segs);
    img.control_code_page = img.alloc_control_page(&mut f).unwrap();
    for i in 0..img.segments.len() { crate::image::load_segment(&mut img, &mut f, i, &src).unwrap(); }
    img.terminate(&f);

    // Read entries the way the trampoline does — a raw load per address.
    let w = walk::walk(img.head, 4096, |pa| {
        let page = pa & crate::uapi::PAGE_MASK;
        let off = (pa & (PAGE_SIZE - 1)) as usize;
        match f.ptr(page) {
            // SAFETY: `page` is an image-owned indirection page in the fake
            // supply and `off` is inside it.
            Some(p) => unsafe { (p.add(off) as *const u64).read_unaligned() },
            None => 0,
        }
    });
    assert_eq!(w.end, walk::End::Done);
    // Four destination pages, in segment order, each one page on from the last
    // within its own segment.
    let dsts: Vec<u64> = w.copies.iter().map(|c| c.dst).collect();
    assert_eq!(dsts, [0x20_0000, 0x20_1000, 0x20_2000, 0x60_0000]);
    // Every source is a page the image staged, and no source is also a
    // destination — the invariant the whole staging algorithm exists for.
    for c in &w.copies { assert!(!dsts.contains(&c.src), "source {:#x} is a destination", c.src); }
    img.free(&mut f);
}

#[test]
fn an_unterminated_chain_is_visible_before_the_jump_not_after() {
    let _g = test_lock();
    let mut f = FakeFrames::new(0x80_0000);
    let src = PatternSource::new(PAGE_SIZE as usize);
    let segs = alloc::vec![seg(0x20_0000, PAGE_SIZE)];
    let mut img = KImage::new(0x20_0000, ImageType::Default, segs);
    img.control_code_page = img.alloc_control_page(&mut f).unwrap();
    crate::image::load_segment(&mut img, &mut f, 0, &src).unwrap();
    // Deliberately NOT terminated.
    let w = walk::walk(img.head, 4096, |pa| {
        let page = pa & crate::uapi::PAGE_MASK;
        let off = (pa & (PAGE_SIZE - 1)) as usize;
        // SAFETY: as above — image-owned page, offset inside it.
        f.ptr(page).map_or(0, |p| unsafe { (p.add(off) as *const u64).read_unaligned() })
    });
    assert_eq!(w.end, walk::End::Unterminated);
    img.free(&mut f);
}
