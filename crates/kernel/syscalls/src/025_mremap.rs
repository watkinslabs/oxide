// 025 mremap — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

fn err_from_vmm(e: vmm::Error) -> i64 {
    use syscall::errno::Errno;
    let errno = match e {
        vmm::Error::NotImplemented => Errno::Enosys,
        vmm::Error::NoMem          => Errno::Enomem,
        vmm::Error::Inval          => Errno::Einval,
        vmm::Error::Fault          => Errno::Efault,
        vmm::Error::Perm           => Errno::Eperm,
        vmm::Error::Again          => Errno::Eagain,
        vmm::Error::Access         => Errno::Eacces,
        vmm::Error::Io             => Errno::Eio,
    };
    -(errno.as_i32() as i64)
}

/// `sys_mremap(old, old_sz, new_sz, flags, new_addr)` — slot 25.
///
/// Implementation: shrink-in-place is a partial munmap. Grow-in-place
/// tries to extend the old VMA's end; if the next address is mapped
/// it falls back to mmap-new-region + munmap-old (MREMAP_MAYMOVE).
/// MREMAP_FIXED + new_addr requires the caller-supplied destination
/// be cleared first (Linux semantic).
///
/// MREMAP_MAYMOVE = 1; MREMAP_FIXED = 2; MREMAP_DONTUNMAP = 4.
/// # C: O(K + log N) per VMA-tree op
/// `sys_mremap(old, old_size, new_size, flags, new_addr)` slot 25.
/// ABI shim per `docs/53§4`. Work fn: `vmm::AddressSpace::mremap_full`.
/// # C: O(min(old,new))
pub fn sys_mremap(args: &SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    let einval = -(Errno::Einval.as_i32() as i64);
    let efault = -(Errno::Efault.as_i32() as i64);
    const MREMAP_MAYMOVE:   u64 = 1;
    const MREMAP_FIXED:     u64 = 2;
    const MREMAP_DONTUNMAP: u64 = 4;
    const MREMAP_FLAGS_MASK: u64 = MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;
    let old      = args.a0;
    // Linux PAGE_ALIGNs both sizes up; unaligned inputs are legal. A size in
    // the top page of usize wraps the +0xfff to 0 (a false no-op/zero size) —
    // reject with ENOMEM as Linux does when end overflows past TASK_SIZE.
    let page_mask = hal::PAGE_SIZE_BYTES - 1;
    let old_size = match (args.a1 as usize).checked_add(page_mask as usize) { Some(v) => v & !(page_mask as usize), None => return -(Errno::Enomem.as_i32() as i64) };
    let new_size = match (args.a2 as usize).checked_add(page_mask as usize) { Some(v) => v & !(page_mask as usize), None => return -(Errno::Enomem.as_i32() as i64) };
    let flags    = args.a3;
    let new_addr = args.a4;
    if (flags & !MREMAP_FLAGS_MASK) != 0 {
        return einval;
    }
    if new_size == 0 || new_size as u64 > hal::USER_VA_END {
        return einval;
    }
    let implies_new_addr = (flags & (MREMAP_FIXED | MREMAP_DONTUNMAP)) != 0;
    if implies_new_addr {
        if (flags & MREMAP_MAYMOVE) == 0 {
            return einval;
        }
        if (new_addr & page_mask) != 0 {
            return einval;
        }
        if new_addr > hal::USER_VA_END.saturating_sub(new_size as u64) {
            return einval;
        }
        let old_end = old.checked_add(old_size as u64).ok_or(Errno::Einval)
            .map_err(|e| -(e.as_i32() as i64));
        let new_end = new_addr.checked_add(new_size as u64).ok_or(Errno::Einval)
            .map_err(|e| -(e.as_i32() as i64));
        let (old_end, new_end) = match (old_end, new_end) {
            (Ok(o), Ok(n)) => (o, n),
            (Err(rv), _) | (_, Err(rv)) => return rv,
        };
        if old < new_end && new_addr < old_end {
            return einval;
        }
    }
    if (flags & MREMAP_DONTUNMAP) != 0 && old_size != new_size {
        return einval;
    }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Einval.as_i32() as i64) };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64) };
    let old_ua = match UserVirtAddr::new(old) { Some(u) => u, None => return -(Errno::Einval.as_i32() as i64) };
    // mseal(2): a sealed source range rejects mremap with EPERM.
    if mm.range_sealed(old_ua, old_size) { return -(Errno::Eperm.as_i32() as i64); }
    let new_ua = if implies_new_addr || new_addr != 0 { UserVirtAddr::new(new_addr) } else { None };
    let dontunmap = (flags & MREMAP_DONTUNMAP) != 0;
    // MREMAP_FIXED discards any existing mapping at the destination (Linux
    // semantic). AddressSpace::mmap(fixed) only clears the VMA side — the
    // PTEs must be torn down here or the new mapping silently aliases the
    // old frames (present leaves never fault).
    if (flags & MREMAP_FIXED) != 0 {
        let Some(new_fixed) = new_ua else { return einval };
        if mm.range_sealed(new_fixed, new_size) { return -(Errno::Eperm.as_i32() as i64); }
        // Linux mremap is atomic: a source error (unaligned/hole/multi-VMA/
        // zero size) must leave the caller's destination mapping intact.
        // Validate the source FIRST — glue_munmap frees the destination's
        // frames, so tearing it down before mremap_full's checks would
        // silently destroy live data on an error return (bug_006). Mirror
        // mremap_full's own move-path guards. Shrink (new_size < old_size)
        // never touches new_addr in mremap_full, so it is skipped here.
        if (old & page_mask) != 0 || new_size == 0 {
            return einval;
        }
        let covered_old_len = if new_size < old_size { new_size } else { old_size };
        let Some(covered_end) = old.checked_add(covered_old_len as u64) else {
            return einval;
        };
        match mm.find_vma(old_ua) {
            Some(v) if covered_end <= v.end.as_u64() => {}
            _ => return efault,
        }
        let _ = pmm::user_as::glue_munmap(new_addr, new_size as u64);
    }
    match mm.mremap_full(old_ua, old_size, new_size,
                    (flags & MREMAP_MAYMOVE) != 0,
                    (flags & MREMAP_FIXED) != 0,
                    dontunmap,
                    new_ua)
    {
        Ok(va) => {
            if dontunmap {
                // mremap_full installed the new VMA + copied bytes.
                // Drop the source range's PTEs so subsequent reads
                // on the still-mapped source VMA refault as fresh
                // zero pages — completes the DONTUNMAP contract.
                let _ = pmm::user_as::evict_pages_in_range(old, old_size as u64);
            } else if va.as_u64() != old {
                // B53: MOVE (grow, or FIXED to a new addr). mremap_full
                // copied old→new and removed the *VMA* for the source via
                // AddressSpace::munmap — but that is VMA-bookkeeping only:
                // the source range's PTEs stay mapped and its frames stay
                // allocated (refcount>0, off the buddy free-list). The now
                // VMA-less source VA becomes an allocatable hole; a later
                // mmap reusing it hits the stale PTE (no demand-fault) and
                // silently aliases the *old* frame's contents — musl
                // mallocng then reads non-zero where a fresh group must be
                // zero and trips a_crash() (the python `import` SIGSEGV).
                // Tear the source PTEs + frames down to match Linux mremap.
                let _ = pmm::user_as::evict_pages_in_range(old, old_size as u64);
            } else if new_size < old_size {
                // SHRINK in place: mremap_full dropped the tail VMA only;
                // free the tail's PTEs + frames for the same reason.
                let drop = old.wrapping_add(new_size as u64);
                let _ = pmm::user_as::evict_pages_in_range(drop, (old_size - new_size) as u64);
            }
            va.as_u64() as i64
        }
        Err(e) => err_from_vmm(e),
    }
}
