// Global frame-refcount INVARIANT harness for fork-COW (`11§7`, `11§8`).
//
// Why this exists: the existing `tests_cow_isolation.rs` checks refcount
// against a *hand-maintained* expectation in a fixed 3-way script. It never
// asserts the TRUE global invariant
//
//     refcount(pa) == (# live user PTEs across ALL address spaces -> pa)
//                     + base_holds(pa)            // inode pin for shmem
//
// after every operation, and never randomizes the op stream. A subtle
// fork-COW refcount UNDER-COUNT (a frame whose refcount drops below its live
// mapping count, then is freed + reused while still mapped -> the live-gnome
// random-process SIGSEGV) is invisible to that script.
//
// This harness drives the REAL production code paths:
//   * `AddressSpace::fork_cow_pages`           (fork / fork-of-child)
//   * `AddressSpace::handle_page_fault_cow_rmap` with the SAME closure
//     wiring the kernel fault dispatcher uses (real inc/dec/refcount/alloc)
//   * `AddressSpace::munmap` + a faithful model of `glue_munmap` /
//     `as_teardown` (unmap-then-dec per present leaf)
// over a multi-AS page-table model (one leaf map per root, switched via
// `MmuOps::activate` like CR3), a real struct-page refcount map, a real
// free-list with the production "never hand out a refcount!=0 frame" guard,
// and asserts the global invariant after EVERY op across 200k randomized ops.
//
// A refcount UNDER-COUNT shows up two ways, both asserted here:
//   (1) a live PTE points at a frame whose refcount is 0 (freed while mapped),
//   (2) refcount(pa) < live-PTE-count(pa) + base.
// An over-count (leak) is asserted too (refcount > count) so the harness is a
// strict equality check, not a one-sided one.

#![cfg(test)]

use alloc::sync::Arc;
use core::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::thread_local;
use std::vec::Vec;

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

use crate::address_space::AddressSpace;
use crate::vma::{FaultAccess, FaultKind, FileBacking, VmaBacking, VmaFlags, VmaProt};

const PAGE: u64 = 0x1000;

thread_local! {
    /// root_pa -> (va -> (pa, flags)). One leaf map per address space.
    static ROOTS: RefCell<HashMap<u64, HashMap<u64, (u64, u64)>>> = RefCell::new(HashMap::new());
    /// The "active CR3": which root map/translate operate on.
    static ACTIVE: RefCell<u64> = RefCell::new(0);
    /// pa -> struct-page refcount (the thing pmm tracks). Only inc/dec/alloc
    /// touch this — map/unmap NEVER do, exactly like the real kernel.
    static RC: RefCell<HashMap<u64, i64>> = RefCell::new(HashMap::new());
    /// pa -> base holds (inode pin for shmem/memfd frames). Constant per frame.
    static BASE: RefCell<HashMap<u64, i64>> = RefCell::new(HashMap::new());
    /// Frames currently on the free list (refcount hit 0). Reuse models the
    /// real allocator handing a freed frame back out.
    static POOL: RefCell<Vec<u64>> = RefCell::new(Vec::new());
    /// memfd backing: file_off -> persistent shared frame pa.
    static SHFRAMES: RefCell<HashMap<u64, u64>> = RefCell::new(HashMap::new());
    /// Recorded invariant violation (first one wins). None = clean.
    static BUG: RefCell<Option<std::string::String>> = RefCell::new(None);
}

fn reset() {
    ROOTS.with(|r| r.borrow_mut().clear());
    RC.with(|r| r.borrow_mut().clear());
    BASE.with(|r| r.borrow_mut().clear());
    POOL.with(|r| r.borrow_mut().clear());
    SHFRAMES.with(|r| r.borrow_mut().clear());
    ACTIVE.with(|a| *a.borrow_mut() = 0);
    BUG.with(|b| *b.borrow_mut() = None);
}

fn record_bug(s: std::string::String) {
    BUG.with(|b| { if b.borrow().is_none() { *b.borrow_mut() = Some(s); } });
}

fn activate(root: u64) { ACTIVE.with(|a| *a.borrow_mut() = root); }

// ---- struct-page refcount primitives (the ONLY mutators of RC) ----

/// Real 4 KiB host frame so the COW copy (hhdm=0 -> identity) touches valid
/// memory. Leaked; the test process is short-lived.
fn fresh_pa() -> u64 {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(4096, 4096).unwrap();
    // SAFETY: non-zero 4 KiB layout; alloc_zeroed yields a valid aligned block.
    (unsafe { alloc_zeroed(layout) }) as u64
}

/// Model of `pmm::setup::alloc_one_frame`: prefer a freed frame off the pool,
/// but NEVER hand out one whose refcount is non-zero (the production guard at
/// `setup.rs:339`); set refcount to 1 on success.
fn alloc_frame() -> Option<u64> {
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
    Some(pa)
}

fn rc_inc(pa: u64) {
    RC.with(|r| { *r.borrow_mut().entry(pa).or_insert(0) += 1; });
}

/// Model of `pmm::setup::dec_and_maybe_free_frame`: drop one ref; on 0 the
/// frame returns to the free list (reusable).
fn rc_dec(pa: u64) {
    let new = RC.with(|r| {
        let mut m = r.borrow_mut();
        let e = m.entry(pa).or_insert(0);
        *e -= 1;
        *e
    });
    if new < 0 {
        record_bug(std::format!("OVER-DEC: pa={:#x} refcount went to {}", pa, new));
    }
    if new == 0 {
        POOL.with(|p| p.borrow_mut().push(pa));
    }
}

fn rc_get(pa: u64) -> u32 {
    RC.with(|r| (*r.borrow().get(&pa).unwrap_or(&0)).max(0) as u32)
}

// ---- multi-AS page-table model. map/unmap NEVER touch RC. ----

struct MultiMmu;
impl MmuOps for MultiMmu {
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, _s: PageSize) {
        let root = ACTIVE.with(|a| *a.borrow());
        ROOTS.with(|r| { r.borrow_mut().entry(root).or_default().insert(va.0, (pa.0, flags.bits())); });
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
    unsafe fn map_at(root_pa: u64, va: Va, pa: Pa, flags: PageFlags, _s: PageSize) {
        ROOTS.with(|r| { r.borrow_mut().entry(root_pa).or_default().insert(va.0, (pa.0, flags.bits())); });
    }
    unsafe fn activate(root_pa: u64) { activate(root_pa); }
}

// ---- shmem (memfd) file backing with persistent shared frames ----

struct MemfdBacking;
impl FileBacking for MemfdBacking {
    fn read_at(&self, _off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        for b in dst.iter_mut() { *b = 0; }
        Ok(dst.len())
    }
    fn size_hint(&self) -> u64 { 1 << 30 }
    fn ino(&self) -> u64 { 0x6d65_6d66_6400 }
    fn shared_frame(&self, off: u64) -> Option<u64> {
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
        Some(pa)
    }
}

/// Private-file backing (no shared_frame; MAP_PRIVATE COW snapshot).
struct PrivFileBacking;
impl FileBacking for PrivFileBacking {
    fn read_at(&self, _off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        for b in dst.iter_mut() { *b = 0; }
        Ok(dst.len())
    }
    fn size_hint(&self) -> u64 { 1 << 30 }
}

// ---- the global invariant ----

/// After every op: refcount(pa) == live-PTE-count(pa) + base(pa) for every
/// frame, and no live PTE references a freed (pooled, refcount-0) frame.
fn check_invariant(label: &str) {
    // Tally live PTEs across all roots.
    let mut live: HashMap<u64, i64> = HashMap::new();
    let freed: HashSet<u64> = POOL.with(|p| p.borrow().iter().copied().collect());
    ROOTS.with(|roots| {
        for (root, leaves) in roots.borrow().iter() {
            for (va, (pa, _)) in leaves.iter() {
                let pa = *pa & !(PAGE - 1);
                *live.entry(pa).or_insert(0) += 1;
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
    }
}

// ---- harness driver ----

struct Xorshift(u64);
impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        self.0 = x; x
    }
    fn pick(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind { Anon, FilePriv, FileShared, KernelBytes }

struct AsSlot {
    root: u64,
    mm: Arc<AddressSpace>,
}

/// Enumerate a random page VA inside any VMA of `mm`. Returns (va, prot_w).
fn pick_page(mm: &AddressSpace, rng: &mut Xorshift) -> Option<(u64, bool)> {
    let tree = mm.vmas_for_test();
    let vmas: Vec<(u64, u64, bool)> = tree.iter()
        .map(|v| (v.start.as_u64(), v.end.as_u64(), v.prot.contains(VmaProt::WRITE)))
        .collect();
    if vmas.is_empty() { return None; }
    let (s, e, w) = vmas[rng.pick(vmas.len())];
    let npages = ((e - s) / PAGE).max(1);
    let va = s + (rng.next() % npages) * PAGE;
    Some((va, w))
}

fn pte_at(root: u64, va: u64) -> Option<(u64, u64)> {
    ROOTS.with(|r| r.borrow().get(&root).and_then(|m| m.get(&va).copied()))
}

const COW_WRITE: FaultKind = FaultKind::Protection { access: FaultAccess::Write };
const DEMAND_WRITE: FaultKind = FaultKind::NotPresent { access: FaultAccess::Write };
const DEMAND_READ: FaultKind = FaultKind::NotPresent { access: FaultAccess::Read };

/// Drive one fault (demand or COW) at `va` in the active AS.
fn do_fault(mm: &AddressSpace, va: u64, fault: FaultKind) {
    let uva = match hal::UserVirtAddr::new(va) { Some(u) => u, None => return };
    // SAFETY: hosted harness; MultiMmu active root set to `mm`; closures mirror
    // the kernel fault dispatcher's real inc/dec/refcount/alloc/rmap wiring.
    let _ = unsafe {
        mm.handle_page_fault_cow_rmap::<MultiMmu, _, _, _, _, _>(
            uva, fault, 0,
            alloc_frame,
            rc_get,
            rc_dec,
            |_pa, _av, _idx| {},
            rc_inc,
        )
    };
}

/// Model `glue_munmap`: unmap-then-dec each present leaf in [addr,addr+len),
/// then drop the VMA bookkeeping.
fn do_munmap(slot: &AsSlot, addr: u64, len: u64) {
    activate(slot.root);
    let pages: Vec<(u64, u64)> = ROOTS.with(|r| {
        r.borrow().get(&slot.root).map(|m| {
            m.iter().filter(|(va, _)| **va >= addr && **va < addr + len)
                .map(|(va, (pa, _))| (*va, *pa & !(PAGE - 1))).collect()
        }).unwrap_or_default()
    });
    for (va, pa) in pages {
        // SAFETY: hosted; unmap-before-dec per glue_munmap leaf order.
        unsafe { MultiMmu::unmap(Va(va), PageSize::P4K); }
        rc_dec(pa);
    }
    if let Some(a) = hal::UserVirtAddr::new(addr) {
        let _ = slot.mm.munmap(a, len as usize);
    }
}

/// Model `as_teardown`: dec every present user leaf, drop the root.
fn do_exit(slot: &AsSlot) {
    let pages: Vec<u64> = ROOTS.with(|r| {
        r.borrow().get(&slot.root).map(|m| m.values().map(|(pa, _)| *pa & !(PAGE - 1)).collect())
            .unwrap_or_default()
    });
    for pa in pages { rc_dec(pa); }
    ROOTS.with(|r| { r.borrow_mut().remove(&slot.root); });
}

fn map_region(slot: &AsSlot, kind: Kind, len: u64) {
    let (prot, flags, backing) = match kind {
        Kind::Anon => (
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous),
        Kind::FilePriv => (
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE,
            VmaBacking::File { backing: Arc::new(PrivFileBacking), off: 0 }),
        Kind::FileShared => (
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::SHARED,
            VmaBacking::File { backing: Arc::new(MemfdBacking), off: 0 }),
        Kind::KernelBytes => {
            let data: Arc<[u8]> = Arc::from(std::vec![0xABu8; len as usize].into_boxed_slice());
            (VmaProt::READ | VmaProt::WRITE,
             VmaFlags::PRIVATE,
             VmaBacking::KernelBytes { data, off: 0 })
        }
    };
    let _ = slot.mm.mmap(None, len as usize, prot, flags, backing, false);
}

/// The core randomized invariant test. `seed` + `iters` parametrize the run.
fn run(seed: u64, iters: usize) {
    reset();
    let mut rng = Xorshift(seed);
    let mut next_root: u64 = 0x1_0000_0000;
    let mut slots: Vec<AsSlot> = Vec::new();

    // Seed with a couple of root ASes carrying a mix of backings.
    for _ in 0..2 {
        let root = next_root; next_root += 0x1000_0000;
        let mm = AddressSpace::new(root).expect("AS::new");
        let s = AsSlot { root, mm };
        map_region(&s, Kind::Anon, 8 * PAGE);
        map_region(&s, Kind::FilePriv, 4 * PAGE);
        map_region(&s, Kind::FileShared, 4 * PAGE);
        map_region(&s, Kind::KernelBytes, 4 * PAGE);
        slots.push(s);
    }

    for i in 0..iters {
        if slots.is_empty() {
            let root = next_root; next_root += 0x1000_0000;
            let mm = AddressSpace::new(root).expect("AS::new");
            let s = AsSlot { root, mm };
            map_region(&s, Kind::Anon, 8 * PAGE);
            slots.push(s);
        }
        let op = rng.pick(100);
        let si = rng.pick(slots.len());
        let root = slots[si].root;
        match op {
            // ---- fault (demand or COW) ----
            0..=44 => {
                activate(root);
                if let Some((va, w)) = pick_page(&slots[si].mm, &mut rng) {
                    match pte_at(root, va) {
                        None => {
                            let f = if w && rng.pick(2) == 0 { DEMAND_WRITE } else { DEMAND_READ };
                            do_fault(&slots[si].mm, va, f);
                        }
                        Some((_, flags)) => {
                            // Present: a write to a W-stripped page triggers COW.
                            let pf = PageFlags::from_bits_truncate(flags);
                            if w && !pf.contains(PageFlags::WRITE) {
                                do_fault(&slots[si].mm, va, COW_WRITE);
                            }
                        }
                    }
                }
            }
            // ---- fork (any AS -> child; covers fork-of-child) ----
            45..=69 => {
                if slots.len() < 64 {
                    activate(root);
                    let child_root = next_root; next_root += 0x1000_0000;
                    if let Ok(child) = slots[si].mm
                        .fork_cow_pages::<MultiMmu, _>(child_root, 0, rc_inc)
                    {
                        slots.push(AsSlot { root: child_root, mm: child });
                    }
                }
            }
            // ---- munmap one page ----
            70..=84 => {
                if let Some((va, _)) = pick_page(&slots[si].mm, &mut rng) {
                    do_munmap(&slots[si], va, PAGE);
                }
            }
            // ---- exit an AS ----
            85..=99 => {
                if slots.len() > 1 {
                    let s = slots.swap_remove(si);
                    do_exit(&s);
                    drop(s.mm);
                }
            }
            _ => unreachable!(),
        }
        check_invariant("op");
        BUG.with(|b| {
            if let Some(msg) = b.borrow().as_ref() {
                panic!("seed={:#x} iter={} op={}: {}", seed, i, op, msg);
            }
        });
    }

    // Drain: exit every remaining AS; invariant must hold at each step and
    // all non-base frames must end freed (refcount 0).
    while let Some(s) = slots.pop() {
        do_exit(&s);
        check_invariant("drain");
        BUG.with(|b| {
            if let Some(msg) = b.borrow().as_ref() { panic!("drain: {}", msg); }
        });
    }
}

// ---- data-coherence: the fork-COW corruption the boot actually hits ----
//
// Refcount stays balanced (the proptest above proves it), but a genuine
// MAP_SHARED (memfd/tmpfs) frame must NOT be COW-split on fork: parent and
// child share ONE backing frame, so a write by either is visible to the other
// and to the file. The live-gnome corruption = a forked process reading a
// STALE private snapshot of a shared journald/systemd memfd page (random
// victim, random garbage -> SIGSEGV). `address_space.rs` forcing every VMA
// through COW on fork (`shared=false`) silently froze the child's shared view.

fn write_tag(pa: u64, tag: &[u8; 4]) {
    // SAFETY: pa is a live 4 KiB host frame from fresh_pa; 4-byte write in-bounds.
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), pa as *mut u8, 4); }
}
fn read_tag(pa: u64) -> [u8; 4] {
    let mut b = [0u8; 4];
    // SAFETY: pa is a live 4 KiB host frame; 4-byte read in-bounds.
    unsafe { core::ptr::copy_nonoverlapping(pa as *const u8, b.as_mut_ptr(), 4); }
    b
}
fn cur_pa(va: u64) -> u64 { MultiMmu::translate(Va(va)).expect("mapped").0 .0 & !(PAGE - 1) }

/// Model a userspace store at `va`: if the PTE is write-protected the CPU
/// faults into the COW handler, then the instruction is retried on the
/// now-writable page. Writes `tag` to whichever frame ends up installed.
fn store(slot: &AsSlot, va: u64, tag: &[u8; 4]) {
    activate(slot.root);
    let (_, flags) = pte_at(slot.root, va).expect("page must be mapped before store");
    if !PageFlags::from_bits_truncate(flags).contains(PageFlags::WRITE) {
        do_fault(&slot.mm, va, COW_WRITE);
    }
    write_tag(cur_pa(va), tag);
}

#[test]
fn fork_does_not_cow_split_shared_memfd() {
    reset();
    let mut next_root = 0x5_0000_0000u64;

    // Parent maps a memfd MAP_SHARED page, faults it in, writes "PAR0".
    let proot = next_root; next_root += 0x1000_0000;
    let pmm = AddressSpace::new(proot).expect("AS::new");
    let _ = pmm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE, VmaFlags::SHARED,
        VmaBacking::File { backing: Arc::new(MemfdBacking), off: 0 }, false);
    let pslot = AsSlot { root: proot, mm: pmm };
    let va = pslot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(proot);
    do_fault(&pslot.mm, va, DEMAND_WRITE);
    let shared_frame = cur_pa(va);
    store(&pslot, va, b"PAR0");
    check_invariant("shared-pre-fork");

    // Fork a child (COW fork). The SHARED frame must stay shared.
    activate(proot);
    let croot = next_root;
    let child = pslot.mm.fork_cow_pages::<MultiMmu, _>(croot, 0, rc_inc).expect("fork");
    let cslot = AsSlot { root: croot, mm: child };
    check_invariant("shared-post-fork");

    // Child writes "CH1_" to the shared page.
    store(&cslot, va, b"CH1_");
    check_invariant("shared-post-child-write");

    // The bug: with `shared=false`, fork W-stripped the page, so the child's
    // store COW-split it into a private frame -> parent + file never see "CH1_".
    activate(proot);
    let parent_sees = read_tag(cur_pa(va));
    let file_sees = read_tag(shared_frame);
    BUG.with(|b| { if let Some(m) = b.borrow().as_ref() { panic!("invariant: {}", m); } });
    assert_eq!(&parent_sees, b"CH1_",
        "MAP_SHARED: parent must observe the child's shared write, got {:?} \
         (fork COW-split the shared memfd frame -> lost-write corruption)", parent_sees);
    assert_eq!(&file_sees, b"CH1_",
        "MAP_SHARED: the backing frame must hold the child's write, got {:?}", file_sees);

    // And a parent write must be visible to the child too (true sharing).
    store(&pslot, va, b"PAR1");
    activate(croot);
    assert_eq!(&read_tag(cur_pa(va)), b"PAR1", "child must observe parent's shared write");
}

#[test]
fn fork_does_cow_split_private_anon() {
    // Control: PRIVATE anon MUST COW-split on write (isolation). Passes both
    // before and after the shared-fix; guards against over-correcting.
    reset();
    let proot = 0x6_0000_0000u64;
    let pmm = AddressSpace::new(proot).expect("AS::new");
    let _ = pmm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, false);
    let pslot = AsSlot { root: proot, mm: pmm };
    let va = pslot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(proot);
    do_fault(&pslot.mm, va, DEMAND_WRITE);
    store(&pslot, va, b"PAR0");

    let croot = 0x6_1000_0000u64;
    activate(proot);
    let child = pslot.mm.fork_cow_pages::<MultiMmu, _>(croot, 0, rc_inc).expect("fork");
    let cslot = AsSlot { root: croot, mm: child };

    store(&cslot, va, b"CH1_");
    activate(proot);
    assert_eq!(&read_tag(cur_pa(va)), b"PAR0", "PRIVATE anon: parent isolated from child write");
    activate(croot);
    assert_eq!(&read_tag(cur_pa(va)), b"CH1_", "PRIVATE anon: child sees its own write");
    check_invariant("anon-isolation");
    BUG.with(|b| { if let Some(m) = b.borrow().as_ref() { panic!("invariant: {}", m); } });
}

#[test]
fn fork_cow_refcount_invariant_proptest() {
    // Several independent seeds; each drives 50k randomized ops (200k total)
    // through the real fork/COW/munmap/teardown code with the global
    // refcount==mapping invariant checked after every single op.
    for seed in [0x9E3779B97F4A7C15u64, 0xD1B54A32D192ED03, 0x2545F4914F6CDD1D, 0x1234_5678_9ABC_DEF1] {
        run(seed, 50_000);
    }
}
