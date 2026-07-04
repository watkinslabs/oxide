use super::*;

pub fn glue_mmap(
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: i64,
    file_off: u64,
    backing: Option<alloc::sync::Arc<dyn vmm::FileBacking>>,
    phys_base: Option<u64>,
) -> Result<u64, i64> {
    use syscall::errno::Errno;
    const MAP_SHARED:  u64 = 0x01;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_FIXED:   u64 = 0x10;
    const MAP_ANON:    u64 = 0x20;
    const MAP_GROWSDOWN: u64       = 0x100;
    const MAP_DENYWRITE: u64       = 0x800;     // no-op since 2.6
    const MAP_EXECUTABLE: u64      = 0x1000;    // no-op since 2.6
    const MAP_LOCKED:    u64       = 0x2000;    // accept as no-op (no swap)
    const MAP_NORESERVE: u64       = 0x4000;    // accept; we don't overcommit
    const MAP_POPULATE:  u64       = 0x8000;    // accept; demand-fault still works
    const MAP_NONBLOCK:  u64       = 0x10000;   // accept; no readahead anyway
    const MAP_STACK:     u64       = 0x20000;   // alias for GROWSDOWN per Linux
    const MAP_HUGETLB:   u64       = 0x40000;   // reject (no huge-tlb yet)
    const MAP_SYNC:      u64       = 0x80000;   // DAX; accept as no-op
    const MAP_FIXED_NOREPLACE: u64 = 0x100000;
    const MAP_UNINITIALIZED: u64   = 0x4000000; // CONFIG_MMAP_ALLOW_UNINITIALIZED
    // Bit-field of all flags we tolerate without semantic effect.
    const MAP_KNOWN: u64 = MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANON
        | MAP_GROWSDOWN | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED
        | MAP_NORESERVE | MAP_POPULATE | MAP_NONBLOCK | MAP_STACK
        | MAP_HUGETLB | MAP_SYNC | MAP_FIXED_NOREPLACE | MAP_UNINITIALIZED;
    // Linux: unknown flags → EINVAL (kernel rejects future bits).
    if (flags & !MAP_KNOWN) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    // MAP_HUGETLB: huge-page backing; v1 has no huge-tlb pool. Reject.
    if (flags & MAP_HUGETLB) != 0 { return Err(-(Errno::Enosys.as_i32() as i64)); }

    // File-backed mmap requires a backing from the caller and a
    // page-aligned offset; anonymous mmap rejects a backing.
    let is_anon = flags & MAP_ANON != 0;
    let _ = fd;
    if is_anon {
        // MAP_SHARED|MAP_ANON carries an anonymous shmem backing object
        // (Linux `shmem_zero_setup`): the caller hands us a frame-backed
        // anonymous tmpfs inode so fork(2) ALIASES the frames (one backing
        // object, no anon_vma, no COW split) and parent/child see each
        // other's writes. MAP_PRIVATE|MAP_ANON is pure zero-fill COW and
        // must NOT carry a backing.
        if phys_base.is_some() { return Err(-(Errno::Einval.as_i32() as i64)); }
        if backing.is_some() && (flags & MAP_SHARED) == 0 {
            return Err(-(Errno::Einval.as_i32() as i64));
        }
    } else if phys_base.is_some() {
        // Device physical mapping (e.g. /dev/fbN, Linux remap_pfn_range):
        // no FileBacking, just a page-aligned offset into the device memory.
        if (file_off & 0xfff) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    } else {
        if backing.is_none()       { return Err(-(Errno::Ebadf.as_i32() as i64)); }
        if (file_off & 0xfff) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    }
    if len == 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    // SHARED + PRIVATE are mutually exclusive per Linux; require
    // exactly one. Linux returns EINVAL when neither is set.
    let is_shared  = flags & MAP_SHARED  != 0;
    let is_private = flags & MAP_PRIVATE != 0;
    if is_shared == is_private { return Err(-(Errno::Einval.as_i32() as i64)); }
    let want_fixed = flags & MAP_FIXED != 0;
    let want_no_replace = flags & MAP_FIXED_NOREPLACE != 0;
    // Linux: MAP_STACK is a NO-OP hint (mman.h: "provided for
    // compatibility"), NOT an alias for MAP_GROWSDOWN — treating it as
    // GROWSDOWN armed the 8 MiB auto-extend under every pthread stack, so a
    // stray fault in a hole below one silently extended the stack over the
    // hole instead of SIGSEGV-ing. Only an explicit MAP_GROWSDOWN grows.
    let want_grows_down = flags & MAP_GROWSDOWN != 0;
    let len_aligned = ((len + 0xfff) & !0xfff) as usize;
    if (want_fixed || want_no_replace) && (addr == 0 || (addr & 0xfff) != 0) {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    // F158: MAP_FIXED_NOREPLACE — Linux 4.17+. Like MAP_FIXED but
    // returns EEXIST instead of clearing overlap. Used by JIT
    // engines that want to verify no clobber. Detect overlap by
    // probing the AS before the insert.
    if want_no_replace {
        if let Some(cur) = sched::live::current() {
            // SAFETY: mm slot single-mutator per `13§5`.
            if let Some(mm) = unsafe { cur.mm_ref() } {
                let probe = match UserVirtAddr::new(addr) {
                    Some(u) => u, None => return Err(-(Errno::Einval.as_i32() as i64)),
                };
                let probe_end = addr.saturating_add(len_aligned as u64);
                let mut p = probe.as_u64();
                while p < probe_end {
                    if let Some(u) = UserVirtAddr::new(p) {
                        if mm.find_vma(u).is_some() {
                            return Err(-(Errno::Eexist.as_i32() as i64));
                        }
                    }
                    p = p.saturating_add(0x1000);
                }
            }
        }
    }
    // MAP_FIXED is destructive per 11§6: tear down the overlap
    // (PTEs + frames + TLB) via glue_munmap, then insert into the
    // now-hole range via the non-fixed path.
    if want_fixed && !want_no_replace {
        let _ = glue_munmap(addr, len_aligned as u64);
    }
    // MAP_FIXED is not an advisory hint: after clearing the destination
    // range above, the VMM must either place the VMA exactly there or fail.
    // Falling back to another hole corrupts ELF loader layout because ld.so
    // computes later segment addresses relative to the requested base.
    let is_fixed = want_fixed;
    let mut vma_flags = if is_shared {
        if is_anon { VmaFlags::SHARED | VmaFlags::ANONYMOUS }
        else       { VmaFlags::SHARED }
    } else if is_anon {
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS
    } else {
        VmaFlags::PRIVATE
    };
    // MAP_GROWSDOWN: stack-style auto-grow on PF within Linux's
    // 64 KiB guard distance below vma.start (used by pthread stacks
    // and ld.so's main stack).
    if want_grows_down { vma_flags |= VmaFlags::GROWSDOWN; }
    let vma_backing = match (phys_base, backing) {
        (Some(pa), _) => VmaBacking::PhysRange { base_pa: pa + file_off },
        (None, Some(b)) => VmaBacking::File { backing: b, off: file_off },
        (None, None)    => VmaBacking::Anonymous,
    };
    let hint = if addr != 0 {
        match UserVirtAddr::new(addr) {
            Some(uva) => Some(uva),
            None      => return Err(-(Errno::Einval.as_i32() as i64)),
        }
    } else {
        None
    };

    // mmap into the current task's AS, not the boot global —
    // post-execve the running CR3 targets `cur.mm`, not the global.
    let r = if let Some(cur) = sched::live::current() {
        // SAFETY: caller is the syscall dispatcher; preempt-off; running task on this CPU is the sole writer of mm slot.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            mm.mmap(
                hint,
                len_aligned,
                prot_from_linux(prot),
                vma_flags,
                vma_backing.clone(),
                is_fixed,
            )
        } else {
            match with(|as_| as_.mmap(
                hint, len_aligned, prot_from_linux(prot),
                vma_flags, vma_backing.clone(), is_fixed,
            )) {
                Some(r) => r,
                None    => return Err(-(Errno::Enosys.as_i32() as i64)),
            }
        }
    } else {
        match with(|as_| as_.mmap(
            hint, len_aligned, prot_from_linux(prot),
            vma_flags, VmaBacking::Anonymous, is_fixed,
        )) {
            Some(r) => r,
            None    => return Err(-(Errno::Enosys.as_i32() as i64)),
        }
    };
    match r {
        Ok(uva)  => Ok(uva.as_u64()),
        // errno fidelity (Linux do_mmap): bad args are EINVAL; only genuine
        // exhaustion (no hole / no frame) is ENOMEM.
        Err(vmm::Error::Inval) => Err(-(Errno::Einval.as_i32() as i64)),
        Err(_)   => Err(-(Errno::Enomem.as_i32() as i64)),
    }
}

/// F128: drop every mapped page in `[addr, addr+len)` WITHOUT
/// touching the VMA(s) that cover the range. Mirrors Linux
/// `MADV_DONTNEED` — anonymous pages refault as zero on next
/// access; file pages refault from the file. Refcount-aware:
/// uses `rmap_aware_dec_and_maybe_free` so COW-shared frames
/// don't get yanked from the peer.
