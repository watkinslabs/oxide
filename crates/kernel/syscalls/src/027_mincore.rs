// 027 mincore — one syscall, one file (docs/53 §0).
#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::errno::Errno;
#[cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;

const PAGE: u64 = 0x1000;
const PAGE_MASK: u64 = PAGE - 1;
const MINCORE_CHUNK_PAGES: u64 = PAGE;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn page_count(len: u64) -> u64 {
    (len >> 12) + if (len & PAGE_MASK) != 0 { 1 } else { 0 }
}

fn user_range_ok(ptr: u64, len: u64) -> bool {
    if len == 0 { return ptr <= hal::USER_VA_END; }
    ptr < hal::USER_VA_END && ptr.checked_add(len).map_or(false, |end| end <= hal::USER_VA_END)
}

fn find_vma<'a>(vmas: &'a [vmm::Vma], addr: u64) -> Option<&'a vmm::Vma> {
    vmas.iter().find(|v| {
        let s = v.start.as_u64();
        let e = v.end.as_u64();
        addr >= s && addr < e
    })
}

/// Linux `do_mincore()` over a stable VMA snapshot. `present` is the PTE-present
/// query; file page-cache residency comes from `FileBacking::mincore_page`.
/// # C: O(npages + N_vmas)
pub(crate) fn mincore_vmas<F>(start: u64, len: u64, out: &mut [u8], vmas: &[vmm::Vma], mut present: F) -> i64
where
    F: FnMut(u64) -> bool,
{
    if (start & PAGE_MASK) != 0 { return err(Errno::Einval); }
    let pages = page_count(len);
    if pages == 0 { return 0; }
    if pages > out.len() as u64 { return err(Errno::Efault); }

    let Some(end) = start.checked_add(pages << 12) else { return err(Errno::Enomem); };
    let mut pos = start;
    let mut wrote = 0usize;
    while pos < end {
        let Some(vma) = find_vma(vmas, pos) else { return err(Errno::Enomem); };
        let seg_end = core::cmp::min(end, vma.end.as_u64());
        let seg_pages = ((seg_end - pos) >> 12) as usize;
        match &vma.backing {
            vmm::VmaBacking::Anonymous => {
                for i in 0..seg_pages {
                    let va = pos + (i as u64) * PAGE;
                    out[wrote + i] = if present(va) { 1 } else { 0 };
                }
            }
            vmm::VmaBacking::File { backing, off } => {
                if !backing.mincore_can_reveal() {
                    out[wrote..wrote + seg_pages].fill(1);
                } else {
                    let base = *off + (pos - vma.start.as_u64());
                    for i in 0..seg_pages {
                        let va = pos + (i as u64) * PAGE;
                        let file_off = base + (i as u64) * PAGE;
                        out[wrote + i] = if present(va) || backing.mincore_page(file_off) { 1 } else { 0 };
                    }
                }
            }
            _ => out[wrote..wrote + seg_pages].fill(1),
        }
        pos = seg_end;
        wrote += seg_pages;
    }
    0
}

#[cfg(target_os = "oxide-kernel")]
fn current_vmas() -> Result<alloc::vec::Vec<vmm::Vma>, Errno> {
    let cur = sched::live::current().ok_or(Errno::Einval)?;
    // SAFETY: mm slot single-mutator per `13§5`; running task on this CPU.
    let mm = unsafe { cur.mm_ref() }.ok_or(Errno::Einval)?;
    Ok(mm.snapshot_vmas())
}

#[cfg(target_os = "oxide-kernel")]
fn page_present(va: u64) -> bool {
    use hal::{MmuOps, Va};
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::X86Mmu::translate(Va(va)).is_some() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::ArmMmu::translate(Va(va)).is_some() }
}

/// `sys_mincore(addr, len, vec)` — slot 27.
/// ABI shim per `docs/53§4`. Work fn: `mincore_vmas`.
/// # C: O(npages + N_vmas)
#[cfg(target_os = "oxide-kernel")]
pub fn sys_mincore(args: &SyscallArgs) -> i64 {
    let (start, len, vec) = (args.a0, args.a1, args.a2);
    if (start & PAGE_MASK) != 0 { return err(Errno::Einval); }
    if !user_range_ok(start, len) { return err(Errno::Enomem); }
    let pages = page_count(len);
    if !user_range_ok(vec, pages) { return err(Errno::Efault); }
    if pages == 0 { return 0; }

    let vmas = match current_vmas() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let mut done = 0u64;
    while done < pages {
        let chunk = core::cmp::min(pages - done, MINCORE_CHUNK_PAGES);
        let addr = start + done * PAGE;
        let mut tmp = alloc::vec![0u8; chunk as usize];
        let rv = mincore_vmas(addr, chunk * PAGE, &mut tmp, &vmas, page_present);
        if rv != 0 { return rv; }
        let dst = vec + done;
        if let Err(rv) = crate::userbuf::validate_user_buf_writable(dst, chunk, 1) { return rv; }
        for (i, b) in tmp.iter().enumerate() {
            // SAFETY: destination chunk was validated writable; byte stores are alignment-independent.
            unsafe { core::ptr::write_unaligned((dst + i as u64) as *mut u8, *b); }
        }
        done += chunk;
    }
    0
}
