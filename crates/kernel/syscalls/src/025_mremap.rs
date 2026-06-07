// 025 mremap — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

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
/// Tier-3 shim per `docs/53§4`. Work fn: `vmm::AddressSpace::mremap_full`.
/// # C: O(min(old,new))
pub fn sys_mremap(args: &SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    const MREMAP_MAYMOVE:   u64 = 1;
    const MREMAP_FIXED:     u64 = 2;
    const MREMAP_DONTUNMAP: u64 = 4;
    let old      = args.a0;
    let old_size = args.a1 as usize;
    let new_size = args.a2 as usize;
    let flags    = args.a3;
    let new_addr = args.a4;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Einval.as_i32() as i64) };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64) };
    let old_ua = match UserVirtAddr::new(old) { Some(u) => u, None => return -(Errno::Einval.as_i32() as i64) };
    // mseal(2): a sealed source range rejects mremap with EPERM.
    if mm.range_sealed(old_ua, old_size) { return -(Errno::Eperm.as_i32() as i64); }
    let new_ua = if new_addr != 0 { UserVirtAddr::new(new_addr) } else { None };
    let dontunmap = (flags & MREMAP_DONTUNMAP) != 0;
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
        Err(_) => -(Errno::Enomem.as_i32() as i64),
    }
}
