use super::*;

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
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
    may_prot: VmaProt,
) -> Result<u64, i64> {
    use syscall::errno::Errno;
    use crate::mmap_flags::{should_populate, validate_glue_admission, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_GROWSDOWN, MAP_LOCKED};
    let admission = validate_glue_admission(flags, len, file_off, backing.is_some(), phys_base.is_some())?;
    let is_anon = admission.is_anon;
    let is_shared = admission.is_shared;
    let len_aligned = admission.len_aligned;
    let populate = should_populate(flags);

    // File-backed mmap requires a backing from the caller and a
    // page-aligned offset; anonymous mmap rejects a backing.
    let _ = fd;
    let want_fixed = flags & MAP_FIXED != 0;
    let want_no_replace = flags & MAP_FIXED_NOREPLACE != 0;
    // Linux: MAP_STACK is a NO-OP hint (mman.h: "provided for
    // compatibility"), NOT an alias for MAP_GROWSDOWN — treating it as
    // GROWSDOWN armed the 8 MiB auto-extend under every pthread stack, so a
    // stray fault in a hole below one silently extended the stack over the
    // hole instead of SIGSEGV-ing. Only an explicit MAP_GROWSDOWN grows.
    let want_grows_down = flags & MAP_GROWSDOWN != 0;
    if (want_fixed || want_no_replace) && (addr == 0 || (addr & PAGE_MASK) != 0) {
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
                    p = p.saturating_add(PAGE_BYTES);
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
    if (flags & MAP_LOCKED) != 0 { vma_flags |= VmaFlags::LOCKED; }
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
            mm.mmap_with_may(
                hint,
                len_aligned,
                prot_from_linux(prot),
                may_prot,
                vma_flags,
                vma_backing.clone(),
                is_fixed,
            )
        } else {
            match with(|as_| as_.mmap_with_may(
                hint, len_aligned, prot_from_linux(prot), may_prot,
                vma_flags, vma_backing.clone(), is_fixed,
            )) {
                Some(r) => r,
                None    => return Err(-(Errno::Enosys.as_i32() as i64)),
            }
        }
    } else {
        match with(|as_| as_.mmap_with_may(
            hint, len_aligned, prot_from_linux(prot), may_prot,
            vma_flags, VmaBacking::Anonymous, is_fixed,
        )) {
            Some(r) => r,
            None    => return Err(-(Errno::Enosys.as_i32() as i64)),
        }
    };
    match r {
        Ok(uva)  => {
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
        Err(vmm::Error::Inval) => Err(-(Errno::Einval.as_i32() as i64)),
        Err(vmm::Error::Access) => Err(-(Errno::Eacces.as_i32() as i64)),
        Err(_)   => Err(-(Errno::Enomem.as_i32() as i64)),
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
            do_handle(mm, uva, FaultKind::NotPresent { access }, hhdm)?;
        }
        va = va.saturating_add(PAGE_BYTES);
    }
    Ok(())
}
