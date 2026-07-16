// Phase C (per-inode address_space / shmem) acceptance harness.
//
// Drives the PRODUCTION file-fault arms in `address_space.rs` against a mock
// `FileBacking` that models a per-inode `address_space` (Linux `i_mapping`):
// one persistent frame per page offset, shared by every mapper of the
// "inode". Same multi-AS page-table + refcount model as
// `tests_cow_isolation.rs` (root_pa = CR3, real RC map), so it exercises the
// exact shared-install (`:1222`/`:1036`), fork-share (`:407`), and
// MAP_PRIVATE COW-copy (`:1055`) paths the boot relies on.
//
// Covers the Phase-C acceptance:
//   T1 — two MAP_SHARED mappers of one inode see each other's writes (ONE
//        address_space: both install the SAME cache frame).
//   T2 — fork of a MAP_SHARED page stays shared (no COW-split; child write
//        visible to parent; refcount == live mappers).
//   T2b — write fault on a (re-)RO'd shared page re-installs the SAME cache
//        frame writable in place (Linux shmem dirty path), no copy/split.
//   T3 — MAP_PRIVATE write COWs a private copy and does NOT touch the cache.
// Deterministic + Miri-clean: `cargo test -p vmm` / `cargo miri test`.

#![cfg(test)]

use alloc::sync::Arc;
use core::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;
use std::thread_local;

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

use crate::address_space::AddressSpace;
use crate::vma::{FaultAccess, FaultKind, FileBacking, VmaBacking, VmaFlags, VmaProt};

const PG: u64 = 4096;

thread_local! {
    static ROOTS: RefCell<HashMap<u64, HashMap<u64, (u64, u64)>>> = RefCell::new(HashMap::new());
    static ACTIVE: RefCell<u64> = RefCell::new(0);
    static RC: RefCell<HashMap<u64, i64>> = RefCell::new(HashMap::new());
}

fn reset() {
    ROOTS.with(|r| r.borrow_mut().clear());
    RC.with(|r| r.borrow_mut().clear());
    ACTIVE.with(|a| *a.borrow_mut() = 0);
}
fn activate_root(root: u64) { ACTIVE.with(|a| *a.borrow_mut() = root); }
fn rc_inc(pa: u64) { RC.with(|r| { *r.borrow_mut().entry(pa).or_insert(0) += 1; }); }
fn rc_dec(pa: u64) { RC.with(|r| { *r.borrow_mut().entry(pa).or_insert(0) -= 1; }); }
fn rc_get(pa: u64) -> i64 { RC.with(|r| *r.borrow().get(&pa).unwrap_or(&0)) }
fn rc_get_u32(pa: u64) -> u32 { rc_get(pa).max(0) as u32 }

/// Real 4 KiB-aligned host frame so the COW copy / shared-frame install
/// (hhdm=0 → pa is the identity host address) touches valid memory. Leaked.
fn fresh_pa() -> u64 {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(4096, 4096).unwrap();
    // SAFETY: non-zero 4 KiB layout; alloc_zeroed yields a valid aligned zeroed block.
    (unsafe { alloc_zeroed(layout) }) as u64
}
fn fresh_pa_opt() -> Option<u64> { Some(fresh_pa()) }

fn write_tag(pa: u64, tag: &[u8; 4]) {
    // SAFETY: pa is a live 4 KiB host allocation; 4-byte write in-bounds.
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
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, _s: PageSize) -> Option<Pa> {
        let root = ACTIVE.with(|a| *a.borrow());
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
    unsafe fn activate(root_pa: u64) { activate_root(root_pa); }
}

/// Mock per-inode `address_space`: page-aligned offset -> persistent host
/// frame, 0xCC-filled on first touch. `shared_frame` hands out THE frame
/// (every mapper aliases it); `read_at` copies its bytes (the MAP_PRIVATE
/// fill source). Shared across mappers via the same `Arc<MockMapping>`.
struct MockMapping { frames: Mutex<HashMap<u64, u64>> }
impl MockMapping {
    fn new() -> Arc<Self> { Arc::new(Self { frames: Mutex::new(HashMap::new()) }) }
    fn frame(&self, off: u64) -> u64 {
        let key = off & !(PG - 1);
        let mut g = self.frames.lock().unwrap();
        *g.entry(key).or_insert_with(|| {
            let p = fresh_pa();
            // SAFETY: p is a fresh 4 KiB host frame; fill the page granule.
            unsafe { core::ptr::write_bytes(p as *mut u8, 0xCC, PG as usize); }
            p
        })
    }
}
impl FileBacking for MockMapping {
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        let f = self.frame(off);
        let n = dst.len().min(PG as usize);
        // SAFETY: f is a live 4 KiB host frame; dst owns >= n bytes; non-overlapping.
        unsafe { core::ptr::copy_nonoverlapping(f as *const u8, dst.as_mut_ptr(), n); }
        Ok(n)
    }
    fn size_hint(&self) -> u64 { PG }
    fn ino(&self) -> u64 { 0x4242 }
    fn shared_frame(&self, off: u64) -> Option<u64> { Some(self.frame(off)) }
}

fn mmap_file(root: u64, va: u64, backing: Arc<dyn FileBacking>, flags: VmaFlags) -> Arc<AddressSpace> {
    let as_ = AddressSpace::new(root).expect("AS::new");
    let s = hal::UserVirtAddr::new(va).expect("va");
    as_.mmap(Some(s), PG as usize, VmaProt::READ | VmaProt::WRITE, flags,
        VmaBacking::File { backing, off: 0 }, true).expect("mmap");
    as_
}

struct DirectMapping { inner: Arc<MockMapping> }
impl FileBacking for DirectMapping {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, ()> { Err(()) }
    fn size_hint(&self) -> u64 { PG }
    fn direct_frame(&self, off: u64) -> Option<u64> { Some(self.inner.frame(off)) }
}

fn fault(as_: &AddressSpace, root: u64, va: u64, fk: FaultKind) {
    activate_root(root);
    // SAFETY: hosted; ACTIVE root set; mock frames are live host memory; hhdm=0 identity.
    unsafe {
        as_.handle_page_fault_cow_rmap::<MultiMmu, _, _, _, _, _, _>(
            hal::UserVirtAddr::new(va).unwrap(), fk, 0,
            fresh_pa_opt, rc_get_u32, rc_dec,
            |_p, _av, _i| {}, rc_inc, |_p| false,
        ).expect("fault");
    }
}

fn cur_pa(root: u64, va: u64) -> u64 {
    activate_root(root);
    MultiMmu::translate(Va(va)).expect("mapped").0 .0 & !(PG - 1)
}

const RD: FaultKind = FaultKind::NotPresent { access: FaultAccess::Read };
const WR: FaultKind = FaultKind::Protection { access: FaultAccess::Write };

/// T1: two MAP_SHARED mappers of ONE inode see each other's writes — both
/// faults install the SAME cache frame (one address_space), not per-backing
/// private copies.
#[test]
fn two_shared_mappers_one_address_space() {
    reset();
    let (r1, r2) = (0x1000, 0x2000);
    let va = 0x10_0000u64;
    let inode = MockMapping::new();
    let f = inode.frame(0);

    let as1 = mmap_file(r1, va, inode.clone(), VmaFlags::SHARED);
    let as2 = mmap_file(r2, va, inode.clone(), VmaFlags::SHARED);
    fault(&as1, r1, va, RD);
    fault(&as2, r2, va, RD);

    assert_eq!(cur_pa(r1, va), f, "AS1 must map the inode's cache frame");
    assert_eq!(cur_pa(r2, va), f, "AS2 must map the SAME cache frame");
    assert_eq!(rc_get(f), 2, "both shared mappers reference the one frame");

    // A write through AS1's mapping is visible through AS2's mapping.
    write_tag(cur_pa(r1, va), b"SHRD");
    assert_eq!(&read_tag(cur_pa(r2, va)), b"SHRD", "MAP_SHARED peers must see the write");
}

/// T2: fork of a MAP_SHARED page stays shared — child write is visible to the
/// parent (no COW-split), refcount tracks the live mappers exactly.
#[test]
fn fork_shared_page_stays_shared() {
    reset();
    let (pr, cr) = (0x1000, 0x2000);
    let va = 0x20_0000u64;
    let inode = MockMapping::new();
    let f = inode.frame(0);

    let parent = mmap_file(pr, va, inode.clone(), VmaFlags::SHARED);
    fault(&parent, pr, va, RD);
    assert_eq!(rc_get(f), 1, "parent maps the shared frame");

    // Fork: SHARED File VMA → NO W-strip, child maps the SAME frame.
    let child = parent.fork_cow_pages::<MultiMmu, _>(cr, 0, rc_inc).expect("fork");
    assert_eq!(rc_get(f), 2, "fork shares the frame: parent + child reference it");
    assert_eq!(cur_pa(pr, va), f, "parent still maps the cache frame");
    assert_eq!(cur_pa(cr, va), f, "child maps the SAME cache frame (no COW-split)");

    // Child writes (its PTE is already writable — shared, never W-stripped);
    // the parent sees it through the shared frame.
    write_tag(cur_pa(cr, va), b"CHLD");
    assert_eq!(&read_tag(cur_pa(pr, va)), b"CHLD", "parent must see the child's shared write");
    assert_eq!(rc_get(f), 2, "no split happened — refcount unchanged");
    let _ = child;
}

/// T2b: a write fault on a shared page that was re-RO'd (mprotect / a prior
/// W-strip) re-installs the SAME cache frame writable in place — no copy, no
/// new frame, no refcount change (Linux shmem dirty path, `:1036`).
#[test]
fn shared_write_fault_reinstalls_same_frame() {
    reset();
    let r = 0x1000;
    let va = 0x30_0000u64;
    let inode = MockMapping::new();
    let f = inode.frame(0);

    let as_ = mmap_file(r, va, inode.clone(), VmaFlags::SHARED);
    fault(&as_, r, va, RD);
    assert_eq!(cur_pa(r, va), f);
    assert_eq!(rc_get(f), 1);

    // Force the PTE read-only (simulate mprotect/W-strip), then write-fault.
    activate_root(r);
    // SAFETY: hosted; re-map the same frame RO under the active root.
    unsafe { MultiMmu::map(Va(va), Pa(f), PageFlags::USER | PageFlags::READ, PageSize::P4K); }
    fault(&as_, r, va, WR);

    assert_eq!(cur_pa(r, va), f, "shared write fault must re-use the SAME cache frame");
    assert_eq!(rc_get(f), 1, "re-install must not change the refcount");
    let (_, flags) = MultiMmu::translate(Va(va)).unwrap();
    assert!(flags.contains(PageFlags::WRITE), "frame must be writable after the dirty fault");
}

/// T3: MAP_PRIVATE write COWs a private copy and does NOT modify the cache —
/// the inode's cache frame keeps its original bytes.
#[test]
fn private_write_does_not_touch_cache() {
    reset();
    let r = 0x1000;
    let va = 0x40_0000u64;
    let inode = MockMapping::new();
    let f = inode.frame(0);
    assert_eq!(&read_tag(f), &[0xCC; 4], "cache starts at the canonical fill");

    let as_ = mmap_file(r, va, inode.clone(), VmaFlags::PRIVATE);
    // Read fault: copy the cache page into a FRESH private frame (not f).
    fault(&as_, r, va, RD);
    let priv1 = cur_pa(r, va);
    assert_ne!(priv1, f, "MAP_PRIVATE fault must NOT alias the cache frame");
    assert_eq!(&read_tag(priv1), &[0xCC; 4], "private copy starts from cache bytes");

    // Write fault: COW into another private frame; write the test tag there.
    fault(&as_, r, va, WR);
    let priv2 = cur_pa(r, va);
    write_tag(priv2, b"PRIV");

    assert_ne!(priv2, f, "the COW copy must be private, not the cache frame");
    assert_eq!(&read_tag(f), &[0xCC; 4], "the inode cache must be UNCHANGED by a private write");
}

#[test]
fn private_direct_mapping_aliases_owner_then_cows_after_fork() {
    reset();
    let (pr, cr) = (0x1000, 0x2000);
    let va = 0x50_0000u64;
    let owner = MockMapping::new();
    let frame = owner.frame(0);
    let backing: Arc<dyn FileBacking> = Arc::new(DirectMapping { inner: owner });
    let parent = mmap_file(pr, va, backing, VmaFlags::PRIVATE);

    fault(&parent, pr, va, RD);
    assert_eq!(cur_pa(pr, va), frame, "direct private fault must install owner frame");
    let child = parent.fork_cow_pages::<MultiMmu, _>(cr, 0, rc_inc).expect("fork");
    assert_eq!(cur_pa(pr, va), frame);
    assert_eq!(cur_pa(cr, va), frame);

    fault(&child, cr, va, WR);
    assert_ne!(cur_pa(cr, va), frame, "private child write must COW after fork");
    assert_eq!(cur_pa(pr, va), frame, "parent retains device owner frame");
}
