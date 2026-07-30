use super::*;

const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

pub fn glue_mmap(
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: i64,
    file_off: u64,
    backing: Option<alloc::sync::Arc<dyn vmm::FileBacking>>,
    phys_base: Option<u64>,
    // A REFCOUNTED kernel RAM frame shared into userspace (io_uring ring).
    // Distinct from `phys_base` (PhysRange / remap_pfn_range) which is
    // UNREFCOUNTED device memory: a kframe must map as `VmaBacking::KernelFrame`
    // so the fault path inc_ref's the struct-page and AS-teardown dec's it —
    // otherwise the mapping is invisible to the frame's refcount/mapcount and
    // the owner freeing its ref (e.g. closing the io_uring fd) frees the page
    // WHILE userspace still maps it (free-while-mapped UAF → heap corruption;
    // the root cause the corruption hunt traced, state.md).
    kframe: Option<u64>,
    may_prot: VmaProt,
) -> Result<u64, i64> {
    use syscall::errno::Errno;
    use crate::mmap_flags::{
        mmap_address_hint, should_populate, validate_glue_admission, MAP_FIXED,
        MAP_FIXED_NOREPLACE, MAP_GROWSDOWN, MAP_LOCKED,
    };
    // A kframe is admission-equivalent to a phys mapping (explicit PA backing,
    // page-aligned offset, not anon).
    let admission = validate_glue_admission(flags, len, file_off, backing.is_some(), phys_base.is_some() || kframe.is_some())?;
    let is_anon = admission.is_anon;
    let is_shared = admission.is_shared;
    let len_aligned = admission.len_aligned;
    let populate = should_populate(flags);

    // File-backed mmap requires a backing from the caller and a
    // page-aligned offset; anonymous mmap rejects a backing.
    let _ = fd;
    let want_fixed = flags & MAP_FIXED != 0;
    let want_no_replace = flags & MAP_FIXED_NOREPLACE != 0;
    let hint = mmap_address_hint(addr, len_aligned as u64, flags)?;
    // Linux: MAP_STACK is a NO-OP hint (mman.h: "provided for
    // compatibility"), NOT an alias for MAP_GROWSDOWN — treating it as
    // GROWSDOWN armed the 8 MiB auto-extend under every pthread stack, so a
    // stray fault in a hole below one silently extended the stack over the
    // hole instead of SIGSEGV-ing. Only an explicit MAP_GROWSDOWN grows.
    let want_grows_down = flags & MAP_GROWSDOWN != 0;
    // MAP_FIXED is destructive per 11§6: tear down the overlap
    // (PTEs + frames + TLB) via glue_munmap, then insert exactly through the
    // canonical VMM placement mode.
    if want_fixed && !want_no_replace {
        // mseal(2): glue_munmap answers -EPERM for a sealed range. Discarding
        // it left the sealed VMAs mapped but let the placement below replace
        // them anyway; propagate so MAP_FIXED over a sealed range fails.
        let rv = glue_munmap(addr, len_aligned as u64);
        if rv < 0 { return Err(rv); }
    }
    // MAP_FIXED is not an advisory hint: after clearing the destination
    // range above, the VMM must either place the VMA exactly there or fail.
    // Falling back to another hole corrupts ELF loader layout because ld.so
    // computes later segment addresses relative to the requested base.
    let placement = match (want_no_replace, want_fixed, hint) {
        (true, _, Some(address)) => vmm::MmapPlacement::FixedNoReplace(address),
        (false, true, Some(address)) => vmm::MmapPlacement::Fixed(address),
        (false, false, hint) => vmm::MmapPlacement::Advisory(hint),
        _ => return Err(-(Errno::Einval.as_i32() as i64)),
    };
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
    if (flags & MAP_LOCKED) != 0 { vma_flags |= VmaFlags::LOCKED; }
    let vma_backing = match (kframe, phys_base, backing) {
        // Refcounted shared kernel RAM frame (single page, io_uring ring):
        // map_kernel_frame inc_ref's on fault, AS-teardown dec's — so the
        // page cannot be freed while a user mapping survives.
        (Some(pa), _, _)       => VmaBacking::KernelFrame { pa },
        (None, Some(pa), _)    => VmaBacking::PhysRange { base_pa: pa + file_off },
        (None, None, Some(b))  => VmaBacking::File { backing: b, off: file_off },
        (None, None, None)     => VmaBacking::Anonymous,
    };
    // mmap into the current task's AS, not the boot global —
    // post-execve the running CR3 targets `cur.mm`, not the global.
    let r = if let Some(cur) = sched::live::current() {
        // SAFETY: caller is the syscall dispatcher; preempt-off; running task on this CPU is the sole writer of mm slot.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            mm.mmap_with_may_at(
                placement,
                len_aligned,
                prot_from_linux(prot),
                may_prot,
                vma_flags,
                vma_backing.clone(),
            )
        } else {
            match with(|as_| as_.mmap_with_may_at(
                placement, len_aligned, prot_from_linux(prot), may_prot,
                vma_flags, vma_backing.clone(),
            )) {
                Some(r) => r,
                None    => return Err(-(Errno::Enosys.as_i32() as i64)),
            }
        }
    } else {
        match with(|as_| as_.mmap_with_may_at(
            placement, len_aligned, prot_from_linux(prot), may_prot,
            vma_flags, VmaBacking::Anonymous,
        )) {
            Some(r) => r,
            None    => return Err(-(Errno::Enosys.as_i32() as i64)),
        }
    };
    match r {
        Ok(uva) => {
            let future_populate = sched::live::current().and_then(|cur| {
                // SAFETY: syscall runs against the current task's stable mm slot.
                unsafe { cur.mm_ref() }.map(|mm| {
                    let (locked, onfault) = mm.mlock_future_policy();
                    locked && !onfault
                })
            }).unwrap_or(false);
            if populate || future_populate {
                let _ = populate_current_range(uva, len_aligned, prot_from_linux(prot));
            }
            Ok(uva.as_u64())
        }
        // errno fidelity (Linux do_mmap): bad args are EINVAL; only genuine
        // exhaustion (no hole / no frame) is ENOMEM.
        Err(vmm::MmapError::Exists) => Err(-(Errno::Eexist.as_i32() as i64)),
        Err(vmm::MmapError::Vmm(vmm::Error::Inval)) => Err(-(Errno::Einval.as_i32() as i64)),
        Err(vmm::MmapError::Vmm(vmm::Error::Access)) => Err(-(Errno::Eacces.as_i32() as i64)),
        // mseal(2): MAP_FIXED over a sealed range.
        Err(vmm::MmapError::Vmm(vmm::Error::Perm)) => Err(-(Errno::Eperm.as_i32() as i64)),
        Err(vmm::MmapError::Vmm(_)) => Err(-(Errno::Enomem.as_i32() as i64)),
    }
}

/// Populate the current task's user page tables over `[start,start+len)`.
/// # C: O(len / PAGE_SIZE)
pub fn populate_current_range(start: UserVirtAddr, len: usize, prot: VmaProt) -> Result<(), vmm::Error> {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; single-mutator mm slot per `13§5`.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            return populate_range(mm, start, len, prot);
        }
    }
    with(|as_| populate_range(as_, start, len, prot)).unwrap_or(Ok(()))
}

fn populate_range(mm: &AddressSpace, start: UserVirtAddr, len: usize, prot: VmaProt) -> Result<(), vmm::Error> {
    use super::fault::do_handle;
    let access = if prot.contains(VmaProt::READ) {
        FaultAccess::Read
    } else if prot.contains(VmaProt::WRITE) {
        FaultAccess::Write
    } else if prot.contains(VmaProt::EXEC) {
        FaultAccess::Exec
    } else {
        return Ok(());
    };
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut va = start.as_u64();
    let end = va.saturating_add(len as u64);
    while va < end {
        if let Some(uva) = UserVirtAddr::new(va) {
            // MAP_POPULATE prefault runs the Linux `__mm_populate` /
            // `__get_user_pages` path, which does not set `FAULT_FLAG_USER`.
            do_handle(mm, uva, FaultKind::NotPresent { access }, hhdm, false)?;
        }
        va = va.saturating_add(PAGE_BYTES);
    }
    Ok(())
}
