use super::*;

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
    if addr == 0 || len == 0 || (addr & 0xfff) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let len_aligned = (len + 0xfff) & !0xfff;
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
            // SAFETY: pa was reachable via the live PT entry just unmapped; rmap_aware_dec_and_maybe_free checks struct-page refcount and only releases when the last mapping drops.
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa.0 & !0xfff); }
        }
        va += 0x1000;
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
    use syscall::errno::Errno;
    use hal::{MmuOps, PageSize, Va};
    if len == 0 || (addr & 0xfff) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // Linux munmap(0, len): aligned, walks the (empty) low range, returns 0.
    if addr == 0 { return 0; }
    let len_aligned = (len + 0xfff) & !0xfff;
    if addr.checked_add(len_aligned).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Einval.as_i32() as i64);
    }
    // DIAG (debug-mount): trace munmap range (the other PTE-zapping path).
    #[cfg(feature = "debug-mount")]
    {
        let tid = sched::live::current().map(|c| c.tid).unwrap_or(0);
        klog::write_raw(b"[mnt] MUNMAP addr="); klog::write_hex_u64(addr);
        klog::write_raw(b" len=");              klog::write_hex_u64(len_aligned);
        klog::write_raw(b" tid=");              klog::write_dec_u64(tid as u64);
        klog::write_raw(b"\n");
    }

    // mm_cpumask snapshot for flush_tlb_others (read once, not per page).
    let mask = current_mm_cpumask();
    let mut va = addr;
    let end = addr + len_aligned;
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
            // SAFETY: pa was reachable via the live PT entry just unmapped; rmap_aware_dec_and_maybe_free only releases to PMM when struct-page refcount drops to zero (no other AS maps this frame).
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa.0 & !0xfff); }
        }
        va += 0x1000;
    }

    // VMA bookkeeping side. Post-execve the running CR3 targets
    // cur.mm — that's where the user's VMAs live, not the global
    // boot AS. Mirror glue_mmap so MAP_FIXED's overlap-clear
    // (via glue_munmap) hits the right AS.
    let uva = match UserVirtAddr::new(addr) {
        Some(u) => u,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let r = if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; sole mm writer.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            Some(mm.munmap(uva, len_aligned as usize))
        } else {
            with(|as_| as_.munmap(uva, len_aligned as usize))
        }
    } else {
        with(|as_| as_.munmap(uva, len_aligned as usize))
    };
    match r {
        Some(Ok(()))  => 0,
        Some(Err(_))  => -(Errno::Einval.as_i32() as i64),
        None          => -(Errno::Enosys.as_i32() as i64),
    }
}

/// setup_arg_pages: eagerly map the anonymous stack pages of `as_` covering
/// `[top-len, top)` into `as_`'s own page table. The boot PID-1 spawn calls
/// this before `build_user_stack` (which runs in boot context, `current()==
/// None`) so the stack writes hit mapped pages instead of demand-faulting —
/// Linux maps the initial stack into the new mm at execve time, never lazily.
/// # C: O(pages)
