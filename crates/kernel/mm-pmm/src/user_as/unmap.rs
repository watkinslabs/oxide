use super::*;
use crate::munmap_range::{validate_munmap_range, MunmapRange};

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
const PAGE_ALIGN_MASK: u64 = !PAGE_MASK;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

/// # C: O(log N_vmas)
fn range_sealed(range: MunmapRange) -> bool {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; read-only mm slot query.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            return mm.range_sealed(range.start, range.len_aligned);
        }
    }
    with(|as_| as_.range_sealed(range.start, range.len_aligned)).unwrap_or(false)
}

pub fn evict_pages_in_range(addr: u64, len: u64) -> i64 {
    // DIAG (debug-syscall): a MADV_DONTNEED/FREE zap of a lib-arena page while a
    // thread holds a lock there (finding #4) loses the in-flight lock/unlock
    // write on refault. Log the range so it can be correlated with a spin.
    #[cfg(feature = "debug-syscall")]
    if (0x7ffff6000000..0x7ffff8000000).contains(&addr) {
        klog::write_raw(b"[ZAPEVICT] addr="); klog::write_hex_u64(addr);
        klog::write_raw(b" len="); klog::write_hex_u64(len);
        klog::write_raw(b" tid="); klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
        klog::write_raw(b"\n");
    }
    use syscall::errno::Errno;
    use hal::{MmuOps, PageSize, Va};
    if addr == 0 || len == 0 || (addr & PAGE_MASK) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let len_aligned = (len + PAGE_MASK) & PAGE_ALIGN_MASK;
    if addr.checked_add(len_aligned).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Einval.as_i32() as i64);
    }
    // DIAG (debug-mount): trace the MADV_DONTNEED range so a spurious zap of a
    // dirtied private-file page (e.g. libc's .bss lock) is visible.
    #[cfg(feature = "debug-mount")]
    {
        let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
        klog::write_raw(b"[mnt] EVICT addr=");  klog::write_hex_u64(addr);
        klog::write_raw(b" len=");              klog::write_hex_u64(len_aligned);
        klog::write_raw(b" tid=");              klog::write_dec_u64(tid as u64);
        klog::write_raw(b"\n");
    }
    // mm_cpumask snapshot for flush_tlb_others (read once, not per page).
    let mask = current_mm_cpumask();
    let mut va = addr;
    let end = addr + len_aligned;
    while va < end {
        // SAFETY: privileged read of live page tables; va validated user-half above.
        #[cfg(target_arch = "x86_64")]
        let translated = <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::translate(Va(va));
        #[cfg(target_arch = "aarch64")]
        let translated = <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::translate(Va(va));
        if let Some((pa, _flags)) = translated {
            // SAFETY: page is currently mapped; unmap is the inverse of demand-page install. The dec_ref-and-maybe-free that follows handles the COW-shared case correctly (Linux: MADV_DONTNEED on a shared page just unmaps the caller's PTE, never frees the underlying frame).
            unsafe {
                #[cfg(target_arch = "x86_64")]
                <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::unmap(Va(va), PageSize::P4K);
                #[cfg(target_arch = "aarch64")]
                <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::unmap(Va(va), PageSize::P4K);
            }
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va); }
            // SMP TLB coherence (`20§5`): invalidate this VA on every OTHER
            // online CPU BEFORE the frame is freed below — a peer thread of
            // the same mm with a stale TLB entry would otherwise touch the
            // frame after it returns to the allocator (use-after-free
            // aliasing). x86-only effect; no-op on UP / aarch64 / hosted.
            // cpumask-targeted (only CPUs that have this mm), not all online.
            hal::tlb::shootdown_others_va(va, mask);
            // debug-fwm: free-while-mapped catch on the MADV_DONTNEED path.
            #[cfg(feature = "debug-fwm")]
            {
                let base = pa.0 & PAGE_ALIGN_MASK;
                if crate::setup::frame_refcount(base) <= 1 {
                    let root = sched::live::current().and_then(|c| unsafe { c.mm_ref() }).map(|mm| mm.root_pa()).unwrap_or(0);
                    let n = crate::setup::fwm_peer_maps(va, base, root, crate::user_as::hhdm_offset());
                    if n > 0 {
                        klog::write_raw(b"[FWM-EVICT] va="); klog::write_hex_u64(va);
                        klog::write_raw(b" pa=");            klog::write_hex_u64(base);
                        klog::write_raw(b" peers=");         klog::write_dec_u64(n as u64);
                        klog::write_raw(b" tid=");           klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                        klog::write_raw(b"\n");
                    }
                }
            }
            // SAFETY: pa was reachable via the live PT entry just unmapped; rmap_aware_dec_and_maybe_free checks struct-page refcount and only releases when the last mapping drops.
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa.0 & PAGE_ALIGN_MASK); }
        }
        va += PAGE_BYTES;
    }
    0
}

/// Wrap `AddressSpace::munmap` + per-page PT unmap + frame free.
/// Walks `[addr, addr+len)`, for each present PTE: translate → unmap
/// → free PA back to PMM → flush_va. Then removes the VMA(s).
/// # C: O(pages) PT walk + O(K log N) VMA remove
pub fn glue_munmap(addr: u64, len: u64) -> i64 {
    // DIAG (debug-syscall): a munmap zap of a lib-arena page (finding #4).
    #[cfg(feature = "debug-syscall")]
    if (0x7ffff6000000..0x7ffff8000000).contains(&addr) {
        klog::write_raw(b"[ZAPMUNMAP] addr="); klog::write_hex_u64(addr);
        klog::write_raw(b" len="); klog::write_hex_u64(len);
        klog::write_raw(b" tid="); klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
        klog::write_raw(b"\n");
    }
    use hal::{MmuOps, PageSize, Va};
    use syscall::errno::Errno;
    let range = match validate_munmap_range(addr, len) {
        Ok(r)  => r,
        Err(e) => return e,
    };
    // mseal(2): direct munmap and MAP_FIXED overlap-clear both route through
    // this glue, so reject sealed ranges before any PTE teardown.
    if range_sealed(range) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // DIAG (debug-mount): trace munmap range (the other PTE-zapping path).
    #[cfg(feature = "debug-mount")]
    {
        let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
        klog::write_raw(b"[mnt] MUNMAP addr="); klog::write_hex_u64(addr);
        klog::write_raw(b" len=");              klog::write_hex_u64(range.len_aligned as u64);
        klog::write_raw(b" tid=");              klog::write_dec_u64(tid as u64);
        klog::write_raw(b"\n");
    }

    // mm_cpumask snapshot for flush_tlb_others (read once, not per page).
    let mask = current_mm_cpumask();
    let mut va = addr;
    let end = range.end;
    while va < end {
        // SAFETY: privileged read of live page tables; va is in user-half range validated above.
        #[cfg(target_arch = "x86_64")]
        let translated = <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::translate(Va(va));
        #[cfg(target_arch = "aarch64")]
        let translated = <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::translate(Va(va));
        if let Some((pa, _flags)) = translated {
            // SAFETY: page is mapped; unmap + frame free are the inverse of demand-page install.
            unsafe {
                #[cfg(target_arch = "x86_64")]
                <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::unmap(Va(va), PageSize::P4K);
                #[cfg(target_arch = "aarch64")]
                <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::unmap(Va(va), PageSize::P4K);
            }
            // B47: dec_ref + maybe free. Refcount-aware: a frame
            // shared with a forked peer AS (still mapped there via
            // COW) stays alive; only the unconditional free_one_frame
            // path would yank it out from under the peer. dhcpcd's
            // double-fork daemonize triggers this — the launcher's
            // free → munmap → unmap_pte for the if_options heap was
            // freeing pages still mapped in the grandchild's AS,
            // corrupting grandchild's view of the same struct.
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va); }
            // SMP TLB coherence (`20§5`): flush this VA on every OTHER online
            // CPU BEFORE the frame is freed below, so a peer thread of the
            // same mm can't touch a freed+realloc'd frame through a stale TLB
            // entry. x86-only effect; no-op on UP / aarch64 / hosted.
            // cpumask-targeted (only CPUs that have this mm), not all online.
            hal::tlb::shootdown_others_va(va, mask);
            // debug-fwm: free-while-mapped catch on the MUNMAP path. This dec is
            // about to (maybe) free `pa`. If its refcount is <=1 (this dec frees
            // it) yet a PEER address space still maps this VA→pa, the refcount
            // was UNDER-counted — the same free-while-mapped as the teardown
            // check, but caught at munmap (the dhcpcd/grandchild path). Names
            // the culprit: va, pa, how many peers still map it, and the tid.
            #[cfg(feature = "debug-fwm")]
            {
                let base = pa.0 & PAGE_ALIGN_MASK;
                if crate::setup::frame_refcount(base) <= 1 {
                    let root = sched::live::current().and_then(|c| unsafe { c.mm_ref() }).map(|mm| mm.root_pa()).unwrap_or(0);
                    let n = crate::setup::fwm_peer_maps(va, base, root, crate::user_as::hhdm_offset());
                    if n > 0 {
                        klog::write_raw(b"[FWM-MUNMAP] va="); klog::write_hex_u64(va);
                        klog::write_raw(b" pa=");             klog::write_hex_u64(base);
                        klog::write_raw(b" peers=");          klog::write_dec_u64(n as u64);
                        klog::write_raw(b" tid=");            klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                        klog::write_raw(b"\n");
                    }
                }
            }
            // SAFETY: pa was reachable via the live PT entry just unmapped; rmap_aware_dec_and_maybe_free only releases to PMM when struct-page refcount drops to zero (no other AS maps this frame).
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa.0 & PAGE_ALIGN_MASK); }
        }
        va += PAGE_BYTES;
    }

    // VMA bookkeeping side. Post-execve the running CR3 targets
    // cur.mm — that's where the user's VMAs live, not the global
    // boot AS. Mirror glue_mmap so MAP_FIXED's overlap-clear
    // (via glue_munmap) hits the right AS.
    let r = if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; sole mm writer.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            Some(mm.munmap(range.start, range.len_aligned))
        } else {
            with(|as_| as_.munmap(range.start, range.len_aligned))
        }
    } else {
        with(|as_| as_.munmap(range.start, range.len_aligned))
    };
    match r {
        Some(Ok(()))  => 0,
        Some(Err(_))  => -(Errno::Einval.as_i32() as i64),
        None          => -(Errno::Enosys.as_i32() as i64),
    }
}
