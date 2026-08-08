// 010 mprotect — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use hal::UserVirtAddr;
use syscall::errno::Errno;

/// `sys_mprotect(addr, len, prot)` — slot 10. Linux `mprotect` is
/// `do_mprotect_pkey(start, len, prot, -1)`; slot 329 is the same body with a
/// real key, so both share [`do_mprotect_pkey`] and cannot drift.
/// # C: O(len / PAGE_SIZE)
pub fn sys_mprotect(args: &SyscallArgs) -> i64 { do_mprotect_pkey(args, crate::pkey::PKEY_KEEP) }

/// `do_mprotect_pkey`. Updates the VMA's `prot` field and
/// walks the live page tables to flip W/X bits + flush the TLB per `11§6` via
/// `pmm::user_as::mprotect_pages`.
///
/// `pkey` order is load-bearing: Linux validates the address, length and prot
/// FIRST and only then rejects an unallocated key, so `pkey_mprotect` with a
/// bad key AND a misaligned address reports the alignment error.
/// # C: O(len / PAGE_SIZE)
pub fn do_mprotect_pkey(args: &SyscallArgs, pkey: i32) -> i64 {
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
    // Linux takes `mmap_write_lock` and then refuses a key userspace never
    // allocated, before any VMA is touched so a bad key cannot partially apply.
    let pkey_map = mm.pkeys().with_map(|m| *m);
    let pkey_abi = crate::pkey::with_mm(crate::pkey::ARCH, mm.pkeys().arch());
    if !crate::pkey::pkey_mprotect_allows(&pkey_abi, pkey_map, pkey) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let ua = match UserVirtAddr::new(addr) {
        Some(u) => u, None => return -(Errno::Enomem.as_i32() as i64),
    };
    let (ua, len) = match mprotect_range_for_grow(&mm, ua, len, prot) {
        Ok(r) => r,
        Err(e) => return -(e.as_i32() as i64),
    };
    let requested = pmm::user_as::prot_from_linux(prot);
    let key = (pkey != crate::pkey::PKEY_KEEP).then_some(pkey as u8);
    let outcome = match mm.mprotect_user(
        ua, len, requested, sched::personality::read_implies_exec(cur),
        key,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };
    for step in &outcome.steps {
        // SAFETY: each step was committed under this mm's VMA write lock; the
        // active page tables belong to the running task and the PMM walker
        // flushes every stale permission before returning.
        unsafe {
            pmm::user_as::mprotect_pages(
                mm.root_pa(), step.start.as_u64(), step.len, step.prot, step.pkey,
            );
        }
    }
    match outcome.error {
        None => 0,
        Some(vmm::Error::Access) => -(Errno::Eacces.as_i32() as i64),
        Some(vmm::Error::Perm) => -(Errno::Eperm.as_i32() as i64),
        // Linux: an unmapped hole inside the range is ENOMEM.
        Some(_) => -(Errno::Enomem.as_i32() as i64),
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
