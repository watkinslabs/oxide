// B240 short-fill regression: the File demand-fault arm must NOT install a
// partially-zero page when `read_at` returns short for a NON-EOF page. A short
// read on a mid-file page (page-cache build race / block boundary) used to be
// discarded — the unread bytes stayed zero, ld.so read zeros where library
// code/relocation data belonged, and exit(127)'d. The fault must retry-fill the
// file-valid extent and, on a genuine unrecoverable short, fail (SIGBUS) rather
// than install zeros.
//
// Drives the PRODUCTION fault arm (`AddressSpace::handle_page_fault_cow_rmap`)
// against mock `FileBacking`s whose `read_at` returns short.

#![cfg(test)]

use alloc::sync::Arc;
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;
use std::thread_local;

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

use crate::address_space::AddressSpace;
use crate::vma::{FaultAccess, FaultKind, FileBacking, FileBackingError, VmaBacking, VmaFlags, VmaProt};

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

fn fresh_pa() -> u64 {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(4096, 4096).unwrap();
    // SAFETY: non-zero 4 KiB layout; alloc_zeroed yields a valid aligned zeroed block.
    (unsafe { alloc_zeroed(layout) }) as u64
}
fn fresh_pa_opt() -> Option<u64> { Some(fresh_pa()) }

fn read_byte(pa: u64, idx: usize) -> u8 {
    // SAFETY: pa is a live 4 KiB host frame; idx < PG in-bounds.
    unsafe { core::ptr::read(((pa as usize) + idx) as *const u8) }
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

/// Backing whose `read_at` returns SHORT on the first call for a non-EOF page,
/// then supplies the rest on retry. Every byte it "reads" is `0xAB`; the fault
/// must end with the WHOLE valid extent == 0xAB (zero unread bytes), proving
/// the retry filled the page rather than installing the discarded-tail zeros.
struct ShortThenFull { calls: AtomicUsize, size: u64 }
impl FileBacking for ShortThenFull {
    fn read_at(&self, _off: u64, dst: &mut [u8]) -> Result<usize, FileBackingError> {
        let first = self.calls.fetch_add(1, Ordering::SeqCst) == 0;
        // First call: fill only the first half of the requested extent.
        let n = if first { dst.len() / 2 } else { dst.len() };
        for b in &mut dst[..n] { *b = 0xAB; }
        Ok(n)
    }
    fn size_hint(&self) -> u64 { self.size }
    fn ino(&self) -> u64 { 0x5151 }
}

/// Backing for a file that CLAIMS `size` bytes but can only ever supply `real`
/// (< page) — a genuine unrecoverable short for a non-EOF page. The fault must
/// REFUSE to install (free the frame, return the SIGBUS-equivalent error), not
/// zero-fill the missing tail.
struct ShortForever { real: u64, size: u64 }
impl FileBacking for ShortForever {
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, FileBackingError> {
        let avail = self.real.saturating_sub(off) as usize;
        let n = avail.min(dst.len());
        for b in &mut dst[..n] { *b = 0xAB; }
        Ok(n)
    }
    fn size_hint(&self) -> u64 { self.size }
    fn ino(&self) -> u64 { 0x5252 }
}

fn mmap_file(root: u64, va: u64, backing: Arc<dyn FileBacking>) -> Arc<AddressSpace> {
    let as_ = AddressSpace::new(root).expect("AS::new");
    let s = hal::UserVirtAddr::new(va).expect("va");
    as_.mmap(Some(s), PG as usize, VmaProt::READ | VmaProt::WRITE, VmaFlags::PRIVATE,
        VmaBacking::File { backing, off: 0 }, true).expect("mmap");
    as_
}

fn fault(as_: &AddressSpace, root: u64, va: u64) -> Result<(), crate::Error> {
    activate_root(root);
    // SAFETY: hosted; ACTIVE root set; fresh_pa frames are live host memory; hhdm=0 identity.
    unsafe {
        as_.handle_page_fault_cow_rmap::<MultiMmu, _, _, _, _, _, _, _, _>(
            hal::UserVirtAddr::new(va).unwrap(),
            FaultKind::NotPresent { access: FaultAccess::Read }, 0,
            fresh_pa_opt, rc_get_u32, rc_dec,
            |_p, _av, _i| {}, rc_inc, |_p| false,
            || Ok(()), || {},
        )
    }
}

fn cur_pa(root: u64, va: u64) -> u64 {
    activate_root(root);
    MultiMmu::translate(Va(va)).expect("mapped").0 .0 & !(PG - 1)
}

/// A short FIRST read of a mid-file (non-EOF) page must be RETRIED so the whole
/// file-valid extent is filled — no discarded-tail zeros installed.
#[test]
fn short_then_full_retries_to_complete_page() {
    reset();
    let r = 0x1000;
    let va = 0x10_0000u64;
    // size = 2 pages → the page at off 0 is fully in-file: valid == PG.
    let backing: Arc<dyn FileBacking> = Arc::new(ShortThenFull { calls: AtomicUsize::new(0), size: 2 * PG });
    let as_ = mmap_file(r, va, backing);

    fault(&as_, r, va).expect("fault must succeed after retry-fill");

    let pa = cur_pa(r, va);
    // EVERY byte of the valid extent must be the read sentinel — a single 0x00
    // would mean the discarded short-read tail leaked through (the B240 bug).
    for i in 0..PG as usize {
        assert_eq!(read_byte(pa, i), 0xAB, "byte {i} not filled — partial page installed");
    }
}

/// A genuinely unrecoverable short for a non-EOF page must NOT install a
/// partially-zero page: the fault fails (SIGBUS-equivalent) and frees the frame.
#[test]
fn unrecoverable_short_errors_not_partial() {
    reset();
    let r = 0x1000;
    let va = 0x20_0000u64;
    // File claims 2 pages but the backing only ever yields half a page.
    let backing: Arc<dyn FileBacking> = Arc::new(ShortForever { real: PG / 2, size: 2 * PG });
    let as_ = mmap_file(r, va, backing);

    let res = fault(&as_, r, va);
    assert!(res.is_err(), "non-EOF short must fail the fault, not install zeros");
    // No leaf installed for the faulting VA.
    activate_root(r);
    assert!(MultiMmu::translate(Va(va)).is_none(), "no partial page may be mapped");
}

/// A page wholly past EOF (valid == 0) is legitimately all-zero and must still
/// succeed — the retry path must not regress pure-BSS / past-EOF faults.
#[test]
fn past_eof_page_zero_fills_ok() {
    reset();
    let r = 0x1000;
    let va = 0x30_0000u64;
    // size = half a page; the faulting page covers [0,PG) → valid = PG/2.
    // Use a backing that supplies exactly `real` then EOF, with real == size.
    let backing: Arc<dyn FileBacking> = Arc::new(ShortForever { real: PG / 2, size: PG / 2 });
    let as_ = mmap_file(r, va, backing);

    fault(&as_, r, va).expect("EOF-straddling page must succeed (tail zero-fill)");
    let pa = cur_pa(r, va);
    for i in 0..(PG / 2) as usize { assert_eq!(read_byte(pa, i), 0xAB, "valid head must be filled"); }
    for i in (PG / 2) as usize..PG as usize { assert_eq!(read_byte(pa, i), 0x00, "EOF tail must be zero"); }
}
