// The fill loop behind UFFDIO_COPY, UFFDIO_ZEROPAGE and UFFDIO_CONTINUE.
//
// One loop, three sources of the page: fresh bytes copied from the monitor,
// zeroes, or the page the backing already holds. Everything after "which frame
// carries the contents" — the hole check, the mapping, the write-protect
// marker, the rmap edge and the accounting — is identical, so a new fill mode
// cannot acquire a second, subtly different install.

use hal::{MmuOps, Pa, PageSize, Va};
use syscall::errno::Errno;

use vmm::address_space::uffd::UffdVma;

use super::super::policy::FillKind;
use super::arch::{flush, hhdm, leaf, set_leaf, Mmu, Walker};
use super::{FillReq, Progress};

/// 4 KiB granule of the fill loop.
const PAGE: u64 = hal::PAGE_SIZE_BYTES;

/// Where one page's contents come from.
enum Source {
    /// A fresh frame this path allocated and must free if the install fails.
    Fresh(u64),
    /// A frame owned by the backing, carrying one mapping reference already.
    Backing(u64),
}

impl Source {
    fn pa(&self) -> u64 { match *self { Source::Fresh(pa) | Source::Backing(pa) => pa } }
}

/// Obtain the frame for one page, already carrying its contents.
/// # C: O(1) + O(page) copy
fn source_for(req: &FillReq, vma: &UffdVma, va: u64, done: u64) -> Result<Source, Errno> {
    let file_off = vma.file_off(va);
    match (req.kind, vma.file.as_ref()) {
        // A continue maps the page the backing ALREADY holds. A backing with
        // no page for this offset is the monitor asking to continue something
        // that was never started.
        (FillKind::Continue, Some((backing, _))) => {
            let off = file_off.ok_or(Errno::Efault)?;
            match backing.fault_around_frame(off) {
                Ok(Some(f)) => Ok(Source::Backing(f.pa)),
                _ => Err(Errno::Efault),
            }
        }
        // A fill into shared storage must land IN the storage, or the monitor
        // would populate a private page while every other mapper of the object
        // still sees a hole.
        (_, Some((backing, _))) => {
            let off = file_off.ok_or(Errno::Efault)?;
            if let Ok(Some(f)) = backing.fault_around_frame(off) {
                // Already present in the backing: refuse rather than overwrite
                // contents another mapper may be using.
                // SAFETY: `f.pa` carries only the prospective mapping reference this probe took, and no PTE was installed from it.
                unsafe { pmm::setup::rmap_aware_dec_and_maybe_free(f.pa); }
                return Err(Errno::Eexist);
            }
            let pa = match backing.shared_frame(off) {
                Ok(Some(f)) => f.pa,
                Ok(None) => return Err(Errno::Einval),
                Err(_) => return Err(Errno::Enomem),
            };
            fill_frame(pa, req, done)?;
            Ok(Source::Backing(pa))
        }
        _ => {
            let pa = pmm::setup::alloc_one_frame().ok_or(Errno::Enomem)?;
            fill_frame(pa, req, done)?;
            Ok(Source::Fresh(pa))
        }
    }
}

/// Write one page's contents through the HHDM mirror.
/// # C: O(page)
fn fill_frame(pa: u64, req: &FillReq, done: u64) -> Result<(), Errno> {
    // SAFETY: `pa` is a frame this fill owns for the duration of the write and its HHDM mirror is kernel-writable for PAGE bytes; a copy source is a user VA already validated against the calling task's address space.
    unsafe {
        let dst = (hhdm() + pa) as *mut u8;
        match req.src {
            Some(s) => core::ptr::copy_nonoverlapping((s + done) as *const u8, dst, PAGE as usize),
            None    => core::ptr::write_bytes(dst, 0, PAGE as usize),
        }
    }
    Ok(())
}

/// Give an anonymous page its reverse-mapping edge and admit it for reclaim,
/// so a monitor-installed page is as tracked as a demand-faulted one. Without
/// the edge, an rmap walk over the mapping cannot find the page at all.
/// # C: O(log N)
fn anon_rmap(mm: &vmm::AddressSpace, vma: &UffdVma, va: u64, pa: u64) {
    let Some(uva) = hal::UserVirtAddr::new(va) else { return };
    let Some(anon) = mm.uffd_anon_vma(uva) else { return };
    let idx = ((va - vma.start) / PAGE) as u32;
    // SAFETY: `pa` is the frame installed at `va` by the map just above, and `anon` is that VMA's live anonymous owner; this records the same rmap edge the demand-fault path records.
    unsafe { pmm::setup::set_anon_rmap_for_pa(pa, &anon, idx); }
    let _ = pmm::setup::admit_anon_lru(pa);
    mm.uffd_mark_anon(uva);
}

/// Install `[req.dst, req.dst+req.len)`, stopping at the first per-page
/// failure and reporting how far it got: the caller turns that into the byte
/// count and the short-fill return.
/// # C: O(len/PAGE) walks + frame work
pub fn fill_pages(mm: &vmm::AddressSpace, req: &FillReq, vma: &UffdVma) -> Progress {
    let flags = vma.prot.to_page_flags();
    let mut done = 0u64;
    while done < req.len {
        let va = req.dst + done;
        let _pt = mm.lock_page_table();
        // The destination must be a hole: a monitor must never overwrite a
        // page the process is already using, and must never bury a poison
        // marker under a fresh page.
        if leaf(mm, va).is_some_and(|l| l != 0) { return (done, Some(Errno::Eexist)); }
        let source = match source_for(req, vma, va, done) { Ok(s) => s, Err(e) => return (done, Some(e)) };
        let pa = source.pa();
        // SAFETY: `pa` carries this page's contents and one reference for the mapping about to be installed; `va` is page-aligned and inside `vma`, which belongs to the address space rooted at `mm.root_pa()`; map_at installs the leaf, allocating intermediate tables from the PMM.
        let displaced = unsafe { <Mmu as MmuOps>::map_at(mm.root_pa(), Va(va), Pa(pa), flags, PageSize::P4K) };
        if let Some(old) = displaced {
            // Lost the race against a concurrent installer between the hole
            // probe and this map: the leaf we tore down still holds its
            // mapping reference, so drop it rather than leak.
            // SAFETY: `old` was reachable only through the leaf map_at just replaced, so its mapping reference is ours to drop.
            unsafe { pmm::setup::rmap_aware_dec_and_maybe_free(old.0); }
        }
        if req.wp {
            if let Some(l) = leaf(mm, va) {
                set_leaf(mm, va, <Walker as hal::pt_walker::PtWalker>::leaf_set_uffd_wp(
                    <Walker as hal::pt_walker::PtWalker>::leaf_wrprotect(l)));
            }
        }
        flush(mm, va);
        if matches!(source, Source::Fresh(_)) { anon_rmap(mm, vma, va, pa); }
        // A displaced leaf (the lost-race arm above) was already counted, so
        // its replacement is a net zero and must not double-count.
        if displaced.is_none() {
            if let Some(uva) = hal::UserVirtAddr::new(va) { mm.account_pte_install_at(uva); }
        }
        done += PAGE;
    }
    (done, None)
}
