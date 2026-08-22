// This machine's real regions, and the read that touches memory.
//
// Everything that DECIDES anything lives in the sibling modules; this file only
// answers "what does this machine actually have" and "copy these bytes". Both
// answers need the running kernel, so neither can be checked without one — the
// layout they feed can be, and is.

extern crate alloc;
use alloc::vec::Vec;

use hal::MmuOps;
use vfs::InodeRef;

use super::{layout, notes, Map, Region};

/// Label the ranges this kernel manages: the kernel image, then usable RAM
/// through the direct map.
///
/// Only memory this kernel can vouch for is described. A fabricated region
/// makes a debugger read an address that is not mapped, which on a running
/// kernel is a fault rather than a wrong answer.
/// # C: O(N regions)
fn regions() -> Vec<Region> {
    let mut out: Vec<Region> = Vec::new();
    let (text_start, text_end) = image_range();
    if text_end > text_start {
        out.push(Region { vaddr: text_start, size: text_end - text_start,
            paddr: phys_of(text_start) });
    }
    let hhdm = pmm::user_as::hhdm_offset();
    for r in pmm::setup::usable_regions() {
        let pa = r.start.0 * hal::PAGE_SIZE_BYTES;
        let len = r.len_pfn * hal::PAGE_SIZE_BYTES;
        if len == 0 { continue; }
        out.push(Region { vaddr: hhdm.wrapping_add(pa), size: len, paddr: Some(pa) });
    }
    out
}

/// The loaded kernel image's virtual extent, page-aligned outward so a
/// described region never begins or ends inside a page a reader would map.
/// # C: O(1)
fn image_range() -> (u64, u64) {
    extern "C" { static __kernel_start: u8; static __kernel_end: u8; }
    let pg = hal::PAGE_SIZE_BYTES;
    let start = core::ptr::addr_of!(__kernel_start) as u64 & !(pg - 1);
    let end = (core::ptr::addr_of!(__kernel_end) as u64 + pg - 1) & !(pg - 1);
    (start, end)
}

/// Physical address behind a kernel virtual address, from the page tables.
/// `None` when nothing is mapped there, which reports as "no physical address"
/// rather than as a guess. # C: O(walk depth)
fn phys_of(va: u64) -> Option<u64> {
    arch_translate(va).map(|pa| pa & !(hal::PAGE_SIZE_BYTES - 1))
}

fn arch_translate(va: u64) -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::X86Mmu::translate(hal::Va(va)).map(|(pa, _)| pa.0) }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::ArmMmu::translate(hal::Va(va)).map(|(pa, _)| pa.0) }
}

/// `e_machine` for the arch this kernel was built for.
const MACHINE: u16 = if cfg!(target_arch = "x86_64") { layout::EM_X86_64 }
    else { layout::EM_AARCH64 };

/// Process-status descriptor size for this arch.
const PRSTATUS_SIZE: usize = if cfg!(target_arch = "x86_64") { notes::PRSTATUS_SIZE_X86_64 }
    else { notes::PRSTATUS_SIZE_AARCH64 };

/// Build the description of this machine, once per read: the region list
/// changes with the memory the kernel manages, so a cached one would describe
/// memory that has moved. # C: O(N regions)
fn map() -> Map {
    let (text_start, _) = image_range();
    let cmdline = cmdline_bytes();
    Map {
        page_offset: pmm::user_as::hhdm_offset(),
        machine: MACHINE,
        regions: regions(),
        notes: notes::segment(PRSTATUS_SIZE, &cmdline, syscall::uts::PROC_SYS_OSRELEASE.trim(),
            hal::PAGE_SIZE_BYTES, text_start),
    }
}

fn cmdline_bytes() -> Vec<u8> {
    let mut b = crate::hooks::cmdline().to_vec();
    while matches!(b.last(), Some(&b'\n') | Some(&0)) { b.pop(); }
    b
}

/// Copy live kernel memory at `va` into `dst`, a page at a time, leaving any
/// page that is not mapped as zeroes.
///
/// The per-page check is what keeps a read of a described-but-unbacked address
/// from faulting inside a syscall: a region is a range of the address space,
/// and not every page of one is necessarily present.
/// # C: O(len)
fn fetch(va: u64, dst: &mut [u8]) {
    let pg = hal::PAGE_SIZE_BYTES;
    let mut done = 0usize;
    while done < dst.len() {
        let at = va.wrapping_add(done as u64);
        let in_page = (pg - (at & (pg - 1))) as usize;
        let n = in_page.min(dst.len() - done);
        if arch_translate(at).is_some() {
            // SAFETY: arch_translate resolved this page in the live kernel page
            // tables immediately above, the destination is a distinct caller
            // buffer, and the copy is clipped to stay inside that one page.
            unsafe { core::ptr::copy_nonoverlapping(at as *const u8, dst[done..].as_mut_ptr(), n); }
        }
        done += n;
    }
}

/// `/proc/kcore` inode. The reported size is the whole described span, because
/// a consumer sizes its seeks from it. # C: O(N regions)
pub fn make_proc_kcore() -> InodeRef {
    super::make_inode(map, fetch)
}
