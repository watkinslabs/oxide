// 010 mprotect — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use hal::UserVirtAddr;
use syscall::errno::Errno;

/// `sys_mprotect(addr, len, prot)` — slot 10. Updates the VMA's
/// `prot` field and walks the live page tables to flip W/X bits +
/// flush the TLB per `11§6` via `pmm::user_as::mprotect_pages`.
/// # C: O(len / PAGE_SIZE)
pub fn sys_mprotect(args: &SyscallArgs) -> i64 {
    use pmm::mmap_flags::{validate_prot, PROT_GROWSDOWN, PROT_GROWSUP};
    let addr = args.a0;
    let prot = args.a2;
    if (prot & (PROT_GROWSDOWN | PROT_GROWSUP)) == (PROT_GROWSDOWN | PROT_GROWSUP) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let page_mask = hal::PAGE_SIZE_BYTES - 1;
    if (addr & page_mask) != 0 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    if args.a1 == 0 { return 0; }
    // Linux PAGE_ALIGNs len up after the alignment/no-op checks. A len in
    // the top page of usize wraps the +0xfff to 0 and is ENOMEM.
    let len  = match (args.a1 as usize).checked_add(page_mask as usize) { Some(v) => v & !(page_mask as usize), None => return -(Errno::Enomem.as_i32() as i64) };
    if len == 0 { return 0; }
    if let Err(e) = validate_prot(prot) { return e; }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    let ua = match UserVirtAddr::new(addr) {
        Some(u) => u, None => return -(Errno::Enomem.as_i32() as i64),
    };
    let (ua, len) = match mprotect_range_for_grow(&mm, ua, len, prot) {
        Ok(r) => r,
        Err(e) => return -(e.as_i32() as i64),
    };
    let vp = pmm::user_as::prot_from_linux(prot);
    // mseal(2): a sealed VMA in the range rejects mprotect with EPERM.
    if mm.range_sealed(ua, len) { return -(Errno::Eperm.as_i32() as i64); }
    match mm.mprotect(ua, len, vp) {
        Ok(()) => {
            // SAFETY: caller is the running task; mm matches active AS; per-AS UP + preempt-off serialises with fault path; mprotect_pages walks PT + flushes TLB so hardware enforces the new permissions.
            unsafe { pmm::user_as::mprotect_pages(mm.root_pa(), addr, len, vp); }
            0
        }
        // Linux: an unmapped hole inside the range is ENOMEM (not EINVAL).
        Err(vmm::Error::Access) => -(Errno::Eacces.as_i32() as i64),
        Err(_) => -(Errno::Enomem.as_i32() as i64),
    }
}

fn mprotect_range_for_grow(
    mm: &vmm::AddressSpace,
    ua: UserVirtAddr,
    len: usize,
    prot: u64,
) -> Result<(UserVirtAddr, usize), Errno> {
    use pmm::mmap_flags::{PROT_GROWSDOWN, PROT_GROWSUP};
    let end = ua.as_u64().checked_add(len as u64).ok_or(Errno::Enomem)?;
    if (prot & PROT_GROWSDOWN) != 0 {
        let probe = UserVirtAddr::new(end.saturating_sub(1)).ok_or(Errno::Enomem)?;
        let vma = mm.find_vma(probe).ok_or(Errno::Enomem)?;
        if vma.start.as_u64() >= end { return Err(Errno::Enomem); }
        if !vma.flags.contains(vmm::VmaFlags::GROWSDOWN) { return Err(Errno::Einval); }
        let new_len = end.checked_sub(vma.start.as_u64()).ok_or(Errno::Enomem)? as usize;
        return Ok((vma.start, new_len));
    }
    let first = mm.find_vma(ua).ok_or(Errno::Enomem)?;
    if first.start.as_u64() > ua.as_u64() { return Err(Errno::Enomem); }
    if (prot & PROT_GROWSUP) != 0 {
        return Err(Errno::Einval);
    }
    Ok((ua, len))
}
