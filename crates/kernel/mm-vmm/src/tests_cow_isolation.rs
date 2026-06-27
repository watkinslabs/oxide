// fork + COW DATA-ISOLATION reproduction harness (`11§7`).
//
// Why this exists: the `tests_rmap_cow.rs` suite uses a SINGLE thread-local
// page table and no-op refcount closures, so it cannot see the two failure
// modes the live-gnome boot exhibits:
//   1. cross-AS data bleed — a write in one process landing in another's
//      page (the "garbage syscall arg / executor-spawn storm" corruption);
//   2. frame refcount UNDER-COUNT — fork/COW miscounting shares so an
//      actually-shared frame reads refcount 1.
//
// This harness models REAL per-AS page tables (keyed by root_pa, switched
// via MmuOps::activate like a real CR3 load) and a REAL refcount map, then
// forks a parent into children, has each write a DISTINCT pattern through
// the production COW handler, and asserts every AS reads back exactly its
// own bytes and the refcount equals the live mapping count at each step.
// Deterministic + Miri-clean: run `cargo test -p vmm` and `cargo miri test`.

#![cfg(test)]

use alloc::sync::Arc;
use core::cell::RefCell;
use std::collections::HashMap;
use std::thread_local;

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

use crate::address_space::AddressSpace;
use crate::vma::{FaultAccess, FaultKind, VmaBacking, VmaFlags, VmaProt};

thread_local! {
    // root_pa -> (va -> (pa, flags)). One leaf map per address space.
    static ROOTS: RefCell<HashMap<u64, HashMap<u64, (u64, u64)>>> = RefCell::new(HashMap::new());
    // The "active CR3": which root translate/map/unmap operate on.
    static ACTIVE: RefCell<u64> = RefCell::new(0);
    // pa -> struct-page refcount, the thing the kernel PMM tracks.
    static RC: RefCell<HashMap<u64, i64>> = RefCell::new(HashMap::new());
}

fn reset() {
    ROOTS.with(|r| r.borrow_mut().clear());
    RC.with(|r| r.borrow_mut().clear());
    ACTIVE.with(|a| *a.borrow_mut() = 0);
}

fn activate_root(root: u64) { ACTIVE.with(|a| *a.borrow_mut() = root); }

fn rc_set(pa: u64, v: i64) { RC.with(|r| { r.borrow_mut().insert(pa, v); }); }
fn rc_inc(pa: u64) { RC.with(|r| { *r.borrow_mut().entry(pa).or_insert(0) += 1; }); }
fn rc_dec(pa: u64) { RC.with(|r| { *r.borrow_mut().entry(pa).or_insert(0) -= 1; }); }
fn rc_get(pa: u64) -> i64 { RC.with(|r| *r.borrow().get(&pa).unwrap_or(&0)) }

/// Real 4 KiB-aligned host frame so the COW copy (hhdm=0 → reads/writes the
/// pa directly) touches valid memory. Leaked; test process is short-lived.
fn fresh_pa() -> u64 {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(4096, 4096).unwrap();
    // SAFETY: non-zero 4 KiB layout; alloc_zeroed yields a valid aligned zeroed block.
    (unsafe { alloc_zeroed(layout) }) as u64
}
fn fresh_pa_opt() -> Option<u64> { Some(fresh_pa()) }

/// Tag a frame's first 4 bytes (via hhdm=0 identity) and read it back.
fn write_tag(pa: u64, tag: &[u8; 4]) {
    // SAFETY: pa is a live 4 KiB host allocation from fresh_pa; 4-byte write in-bounds.
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), pa as *mut u8, 4); }
}
fn read_tag(pa: u64) -> [u8; 4] {
    let mut b = [0u8; 4];
    // SAFETY: pa is a live 4 KiB host allocation; 4-byte read in-bounds.
    unsafe { core::ptr::copy_nonoverlapping(pa as *const u8, b.as_mut_ptr(), 4); }
    b
}

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
    unsafe fn activate(root_pa: u64) { activate_root(root_pa); }
}

fn mk_writable_anon(root: u64, start: u64, end: u64) -> Arc<AddressSpace> {
    let as_ = AddressSpace::new(root).expect("AS::new");
    let s = hal::UserVirtAddr::new(start).expect("va");
    as_.mmap(Some(s), (end - start) as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous, true).expect("mmap");
    as_
}

fn cur_pa(va: u64) -> u64 { MultiMmu::translate(Va(va)).expect("mapped").0 .0 & !0xfff }

const WRITE: FaultKind = FaultKind::Protection { access: FaultAccess::Write };

/// The core reproduction: parent forks two children; parent + each child
/// write a DISTINCT 4-byte tag to the same VA through the real COW handler.
/// Every AS must read back exactly its own tag (no cross-AS bleed), and the
/// shared frame's refcount must track the live mappings exactly.
#[test]
fn fork_cow_three_way_data_isolation() {
    reset();
    let (pr, c1r, c2r) = (0x1000, 0x2000, 0x3000);
    let va = 0x10_0000u64;

    // Parent: install one writable anon page, refcount 1, tagged "PAR0".
    let parent = mk_writable_anon(pr, va, va + 0x1000);
    activate_root(pr);
    let f = fresh_pa();
    rc_set(f, 1);
    // SAFETY: hosted; MultiMmu active root = parent.
    unsafe { MultiMmu::map(Va(va), Pa(f), PageFlags::USER | PageFlags::READ | PageFlags::WRITE, PageSize::P4K); }
    write_tag(f, b"PAR0");

    // Fork two children (COW). Each shared page → inc_ref once.
    let c1 = parent.fork_cow_pages::<MultiMmu, _>(c1r, 0, rc_inc).expect("fork c1");
    assert_eq!(rc_get(f), 2, "after 1st fork the frame is shared by parent+child1");
    let c2 = parent.fork_cow_pages::<MultiMmu, _>(c2r, 0, rc_inc).expect("fork c2");
    assert_eq!(rc_get(f), 3, "after 2nd fork shared by parent+child1+child2 — UNDER-COUNT if <3");

    // child1 writes its tag (COW split off the shared frame).
    activate_root(c1r);
    // SAFETY: hosted COW handler; active root = child1; preconditions per handler doc.
    unsafe { c1.handle_page_fault_cow::<MultiMmu, _, _, _>(
        hal::UserVirtAddr::new(va).unwrap(), WRITE, 0, fresh_pa_opt, rc_get_u32, rc_dec).unwrap(); }
    let f1 = cur_pa(va);
    assert_ne!(f1, f, "child1 must get a fresh frame, not reuse the shared one");
    write_tag(f1, b"CH1_");
    assert_eq!(rc_get(f), 2, "child1's COW split drops the shared refcount to parent+child2");

    // child2 writes its tag.
    activate_root(c2r);
    // SAFETY: hosted COW handler; active root = child2.
    unsafe { c2.handle_page_fault_cow::<MultiMmu, _, _, _>(
        hal::UserVirtAddr::new(va).unwrap(), WRITE, 0, fresh_pa_opt, rc_get_u32, rc_dec).unwrap(); }
    let f2 = cur_pa(va);
    write_tag(f2, b"CH2_");
    assert_eq!(rc_get(f), 1, "only parent still maps the original frame");

    // parent writes its tag last.
    activate_root(pr);
    // SAFETY: hosted COW handler; active root = parent.
    unsafe { parent.handle_page_fault_cow::<MultiMmu, _, _, _>(
        hal::UserVirtAddr::new(va).unwrap(), WRITE, 0, fresh_pa_opt, rc_get_u32, rc_dec).unwrap(); }
    let f3 = cur_pa(va);
    write_tag(f3, b"PAR1");
    assert_eq!(rc_get(f), 0, "no AS maps the original frame after all three split");

    // ISOLATION: each AS reads back exactly its own tag.
    activate_root(pr);  assert_eq!(&read_tag(cur_pa(va)), b"PAR1", "parent data bled");
    activate_root(c1r); assert_eq!(&read_tag(cur_pa(va)), b"CH1_", "child1 data bled");
    activate_root(c2r); assert_eq!(&read_tag(cur_pa(va)), b"CH2_", "child2 data bled");

    // distinct frames all around
    assert!(f != f1 && f != f2 && f != f3 && f1 != f2 && f1 != f3 && f2 != f3,
        "every split must own a distinct frame");
}

/// COW handler bridges refcount as u32; wrap the i64 tracker.
fn rc_get_u32(pa: u64) -> u32 { rc_get(pa).max(0) as u32 }
