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

/// Zap one current-address-space swap PTE under the same PTE lock that
/// serializes swap-in and pageout.  Returning the entry transfers its one PTE
/// reference to the caller, which must immediately release the swap slot.
/// # C: O(walk depth)
fn clear_swap_entry(as_: &AddressSpace, va: u64) -> Option<hal::pt_walker::SwapEntry> {
    let _pt = as_.lock_page_table();
    // SAFETY: the address-space PTE lock is held and HHDM covers this live root.
    let cleared = unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let entry = hal::pt_walker::swap_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, hhdm_offset())?;
            hal::pt_walker::clear_swap_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, entry, hhdm_offset()).then_some(entry)
        }
        #[cfg(target_arch = "aarch64")]
        {
            let entry = hal::pt_walker::swap_entry_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, hhdm_offset())?;
            hal::pt_walker::clear_swap_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, entry, hhdm_offset()).then_some(entry)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { let _ = (as_, va); None }
    };
    if cleared.is_some() { as_.account_swap_remove(); }
    cleared
}

/// Retire one present leaf (or migration marker, which this kernel accounts as
/// still-resident until it resolves) from the resident-set counters of the
/// address space this zap loop walks. Linux does the same inside
/// `zap_pte_range` via `add_mm_rss_vec`; without it `anon_pte_mappings` and
/// `file_pte_mappings` only ever grow, so `VmRSS`, `statm` and `ru_maxrss`
/// drift upward without bound for any process that unmaps anything.
/// Resolution mirrors `clear_current_swap_entry`: the running task's mm is
/// authoritative, and the boot address space is the pre-installation fallback.
/// # C: O(log N_vmas)
fn account_present_removed(va: u64) {
    let Some(uva) = hal::UserVirtAddr::new(va) else { return; };
    if let Some(cur) = sched::live::current() {
        // SAFETY: syscall context is the current task's sole address-space writer.
        if let Some(mm) = unsafe { cur.mm_ref() } { mm.account_pte_remove_at(uva); return; }
    }
    let _ = with(|as_| as_.account_pte_remove_at(uva));
}

/// Resolve the active task's authoritative address space, falling back only
/// before task-mm installation to the boot address space used by syscall glue.
/// # C: O(walk depth)
fn clear_current_swap_entry(va: u64) -> Option<hal::pt_walker::SwapEntry> {
    if let Some(cur) = sched::live::current() {
        // SAFETY: syscall context is the current task's sole address-space writer.
        if let Some(mm) = unsafe { cur.mm_ref() } { return clear_swap_entry(mm, va); }
    }
    with(|as_| clear_swap_entry(as_, va)).flatten()
}

/// Remove one exact migration marker.  Unlike swap, this transfers no slot
/// reference: it only drops this PTE's participation in the in-flight
/// transaction so commit/rollback can retire its token safely.
fn clear_migration_entry(as_: &AddressSpace, va: u64) -> Option<hal::pt_walker::MigrationEntry> {
    let _pt = as_.lock_page_table();
    // SAFETY: PTE lock is held and this AS root is live under HHDM.
    #[cfg(target_arch = "x86_64")]
    let cleared = unsafe {
        let entry = hal::pt_walker::migration_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, hhdm_offset())?;
        hal::pt_walker::clear_migration_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, entry, hhdm_offset()).then_some(entry)
    };
    // SAFETY: same held PTE lock, live borrowed root and HHDM coverage as the
    // x86_64 arm above; only the walker type differs.
    #[cfg(target_arch = "aarch64")]
    let cleared = unsafe {
        let entry = hal::pt_walker::migration_entry_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, hhdm_offset())?;
        hal::pt_walker::clear_migration_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, entry, hhdm_offset()).then_some(entry)
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let cleared = { let _ = (as_, va); None };
    cleared
}

fn clear_current_migration_entry(va: u64) -> Option<hal::pt_walker::MigrationEntry> {
    if let Some(cur) = sched::live::current() {
        // SAFETY: syscall context owns this task's AS mutation.
        if let Some(mm) = unsafe { cur.mm_ref() } { return clear_migration_entry(mm, va); }
    }
    with(|as_| clear_migration_entry(as_, va)).flatten()
}

/// Remove a userfaultfd marker of ANY kind. Zapping a range removes the memory
/// the marker described, so leaving it behind would make the NEXT mapping of
/// that address raise a memory error, or report a write-protect fault to a
/// monitor, for a mapping that no longer exists — a `MADV_DONTNEED`ed range
/// must refault as fresh zeroes. Nothing is freed: a marker names no frame and
/// no swap slot.
/// # C: O(walk depth)
fn clear_pte_marker(as_: &AddressSpace, va: u64) -> bool {
    let _pt = as_.lock_page_table();
    // SAFETY: the address-space PTE lock is held and HHDM covers this live root; a marker leaf is non-present, so replacing it with an absent leaf unmaps nothing and drops no reference.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        { clear_marker_at::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va) }
        #[cfg(target_arch = "aarch64")]
        { clear_marker_at::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va) }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { let _ = (as_, va); false }
    }
}

/// # SAFETY: caller holds the address space's page-table lock and owns `root`.
/// # C: O(walk depth)
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn clear_marker_at<W: hal::pt_walker::PtWalker>(root: u64, va: u64) -> bool {
    // SAFETY: per fn contract — the read and the exchange both run under the caller's page-table lock, and the exchange writes only when the leaf still holds exactly the marker it read.
    unsafe {
        let Some(raw) = hal::pt_walker::read_leaf_4k_at_root::<W>(root, va, hhdm_offset())
            else { return false };
        if W::unpack_pte_marker(raw).is_none() { return false; }
        hal::pt_walker::swap_leaf_if_4k_at_root::<W>(root, va, raw, 0, hhdm_offset())
    }
}

/// Run `f` against the address space these zaps operate on: the running task's
/// when there is one, otherwise the global boot one — the same choice the rest
/// of this module makes for its VMA bookkeeping.
/// # C: O(1) + f
fn with_zap_target<R>(f: impl FnOnce(&AddressSpace) -> R) -> Option<R> {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; preempt-off; single-mutator mm slot per 13§5; the closure only reads the VMA tree.
        if let Some(mm) = unsafe { cur.mm_ref() } { return Some(f(mm)); }
    }
    with(f)
}

/// Charge an impending zap of `[start, end)` against every monitor tracking
/// `kind`, so no resolve can land in the range while it is being torn down.
/// # C: O(N_vmas)
fn zap_watchers(start: u64, end: u64, kind: vmm::UffdEventKind)
    -> alloc::vec::Vec<alloc::sync::Arc<dyn vmm::UffdContext>> {
    with_zap_target(|as_| as_.uffd_change_begin(start, end, kind)).unwrap_or_default()
}

/// # C: O(walk depth)
fn clear_current_pte_marker(va: u64) -> bool {
    if let Some(cur) = sched::live::current() {
        // SAFETY: syscall context owns this task's AS mutation.
        if let Some(mm) = unsafe { cur.mm_ref() } { return clear_pte_marker(mm, va); }
    }
    with(|as_| clear_pte_marker(as_, va)).unwrap_or(false)
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
    // A monitor tracking removals is charged for the whole zap BEFORE any
    // page goes, and told about it only once every page has: for the duration
    // its resolves are refused, so it cannot fill a page into a range that is
    // being discarded and then never hear that the range was discarded.
    let watchers = zap_watchers(addr, addr + len_aligned, vmm::UffdEventKind::Remove);
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
            // `MmuOps::unmap` does NOT invalidate on either arch (both walkers
            // just clear the leaf), so the invalidate has to happen here,
            // BEFORE the frame is released below (Linux's invariant order:
            // unhook -> invalidate -> free, never reordered).
            // aarch64 needs this at least as much as x86: `tlbi vae1is` is the
            // ONLY invalidation ARM gets, because `shootdown_others_va` is a
            // no-op there (arm64 has no TLB IPI — the `is` suffix broadcasts in
            // hardware instead). Gating this on x86 left every ARM munmap /
            // MADV_DONTNEED freeing frames with a live writable translation.
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1; dropping
            // a stale translation is always sound.
            unsafe {
                #[cfg(target_arch = "x86_64")]
                { hal_x86_64::flush_local_va(va); }
                #[cfg(target_arch = "aarch64")]
                { hal_aarch64::flush_local_va(va); }
            }
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
                    // SAFETY: `mm_ref` needs no concurrent execve replacing the
                    // mm; this reads the CURRENT task's own slot from inside its
                    // own MADV_DONTNEED syscall, so it is not in execve.
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
            account_present_removed(va);
        } else if let Some(entry) = clear_current_swap_entry(va) {
            // Swap PTEs are non-present and therefore invisible to `translate`.
            // Clear the exact leaf before dropping its slot reference so a fault
            // cannot resurrect a page whose VMA has been zapped.
            hal::tlb::shootdown_others_va(va, mask);
            let _ = crate::swap::free_page(entry);
        } else if clear_current_pte_marker(va) {
            // The marker described contents this zap is discarding; it names
            // no frame and no swap slot, so nothing is released with it.
            hal::tlb::shootdown_others_va(va, mask);
        } else if let Some(marker) = clear_current_migration_entry(va) {
            hal::tlb::shootdown_others_va(va, mask);
            account_present_removed(va);
            if let Some(pa) = vmm::migration_drop_marker_mapping(marker) {
                // SAFETY: removing this marker tears down precisely one
                // original resident PTE reference recorded by its token.
                unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
            }
        }
        va += PAGE_BYTES;
    }
    // Blocks the zapping thread on each monitor until it has read the message,
    // then releases the charge — so the range is already empty when the monitor
    // hears about it, and the monitor is accepting resolves again the moment it
    // has.
    vmm::address_space::uffd::uffd_change_complete(
        watchers, vmm::UffdEvent::Remove { start: addr, end: addr + len_aligned });
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

    // Charged before the first page goes and released only after the monitor
    // has been told the range is gone; every resolve into it is refused in
    // between.
    let watchers = zap_watchers(range.start.as_u64(), range.end, vmm::UffdEventKind::Unmap);
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
            // `MmuOps::unmap` does NOT invalidate on either arch (both walkers
            // just clear the leaf), so the invalidate has to happen here,
            // BEFORE the frame is released below (Linux's invariant order:
            // unhook -> invalidate -> free, never reordered).
            // aarch64 needs this at least as much as x86: `tlbi vae1is` is the
            // ONLY invalidation ARM gets, because `shootdown_others_va` is a
            // no-op there (arm64 has no TLB IPI — the `is` suffix broadcasts in
            // hardware instead). Gating this on x86 left every ARM munmap /
            // MADV_DONTNEED freeing frames with a live writable translation.
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1; dropping
            // a stale translation is always sound.
            unsafe {
                #[cfg(target_arch = "x86_64")]
                { hal_x86_64::flush_local_va(va); }
                #[cfg(target_arch = "aarch64")]
                { hal_aarch64::flush_local_va(va); }
            }
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
                    // SAFETY: `mm_ref` needs no concurrent execve replacing the
                    // mm; this reads the CURRENT task's own slot from inside its
                    // own munmap syscall, so it is not in execve.
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
            account_present_removed(va);
        } else if let Some(entry) = clear_current_swap_entry(va) {
            // `munmap` must release a non-present swap leaf exactly as it
            // releases a present anonymous leaf; otherwise memory.swap.current
            // remains charged after the mapping is gone.
            hal::tlb::shootdown_others_va(va, mask);
            let _ = crate::swap::free_page(entry);
        } else if clear_current_pte_marker(va) {
            // The marker described contents this zap is discarding; it names
            // no frame and no swap slot, so nothing is released with it.
            hal::tlb::shootdown_others_va(va, mask);
        } else if let Some(marker) = clear_current_migration_entry(va) {
            hal::tlb::shootdown_others_va(va, mask);
            account_present_removed(va);
            if let Some(pa) = vmm::migration_drop_marker_mapping(marker) {
                // SAFETY: marker removal transfers this original PTE ref.
                unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
            }
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
    // Announced AFTER the VMAs are gone, whatever the outcome: a monitor is
    // told about pages that have already been torn down, never about a
    // teardown still in progress.
    vmm::address_space::uffd::uffd_change_complete(
        watchers, vmm::UffdEvent::Unmap { start: range.start.as_u64(), end: range.end });
    match r {
        Some(Ok(()))  => 0,
        Some(Err(_))  => -(Errno::Einval.as_i32() as i64),
        None          => -(Errno::Enosys.as_i32() as i64),
    }
}
