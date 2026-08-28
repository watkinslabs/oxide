use super::*;
use crate::munmap_range::{validate_munmap_range, MunmapRange};

mod walk;
use walk::{
    account_present_removed, clear_current_migration_entry, clear_current_pte_marker,
    clear_current_swap_entry, huge_split_refused, range_sealed,
    release_leaf_frame, unmap_leaf, zap_watchers, current_nonpresent_kind, NonpresentKind,
};

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
const PAGE_ALIGN_MASK: u64 = !PAGE_MASK;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

/// Read the present leaf at `va` together with the GRANULE that resolved it.
///
/// A zap loop must never assume the base granule: a hugetlbfs mapping installs

/// Pages a range zap holds before it flushes and frees, mirroring the
/// reference's `mmu_gather` batch. Bounded so a large unmap cannot pin an
/// unbounded list of frames it has already unhooked.
const TLB_GATHER_PAGES: usize = 256;

/// Remote-invalidate every gathered page, then release its frame.
///
/// The reference's `tlb_single_page_flush_ceiling` is 33: above that many
/// pages a range flush costs less as one full remote flush than as one
/// invalidation per page, and here the saving is larger still because each
/// per-page invalidation is its own IPI round-trip.
///
/// The flush strictly precedes every release in the batch, which is the
/// invariant the old per-page order existed to hold: a peer CPU must not be
/// able to reach a freed frame through a stale translation.
/// # C: one IPI round-trip per batch, or one per page below the ceiling
fn drain_gather(gather: &mut alloc::vec::Vec<(u64, u64, hal::PageSize)>, mask: &cpu::CpuMask) {
    if gather.is_empty() { return; }
    const SINGLE_PAGE_FLUSH_CEILING: usize = 33;
    if gather.len() > SINGLE_PAGE_FLUSH_CEILING {
        hal::tlb::shootdown_others_all(mask.as_words());
    } else if gather.len() > 1 {
        let start = gather.first().map(|(va, _, _)| *va).unwrap_or(0);
        let end = gather.last().map(|(va, _, leaf)| va.saturating_add(leaf.bytes())).unwrap_or(start);
        hal::tlb::shootdown_others_range(start, end, mask.as_words());
    } else {
        for (va, _, _) in gather.iter() { hal::tlb::shootdown_others_va(*va, mask.as_words()); }
    }
    for (va, pa, leaf) in gather.drain(..) {
        // SAFETY: the leaf was cleared and every CPU invalidated above, so no
        // translation can still reach the frame; a base page goes back through
        // the rmap-aware path and a huge page back to the pool that owns it.
        unsafe { release_leaf_frame(pa, leaf); }
        #[cfg(feature = "debug-syscost")]
        let account_started = crate::unmapcost::now_ns();
        account_present_removed(va);
        #[cfg(feature = "debug-syscost")]
        crate::unmapcost::account(account_started);
    }
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
    let mask = current_mm_cpumask_full();
    let mut gather: alloc::vec::Vec<(u64, u64, hal::PageSize)> =
        alloc::vec::Vec::with_capacity(TLB_GATHER_PAGES.min(64));
    let mut va = addr;
    let end = addr + len_aligned;
    while va < end {
        let mut step = PAGE_BYTES;
        // Granule read from the tables, never assumed: a hugetlbfs mapping
        // resolves through one block leaf per huge page.
        let translated = unsafe { unmap_leaf(va) };
        let nonpresent = if translated.is_none() {
            current_nonpresent_kind(va)
        } else {
            None
        };
        if let Some((pa_raw, leaf)) = translated {
            step = leaf.bytes();
            let pa = hal::Pa(pa_raw);
            // SAFETY: `unmap_leaf` cleared and locally invalidated the leaf;
            // the dec_ref-and-maybe-free below therefore preserves Linux's
            // clear -> invalidate -> release ordering.
            // SMP TLB coherence (`20§5`): invalidate this VA on every OTHER
            // online CPU BEFORE the frame is freed below — a peer thread of
            // the same mm with a stale TLB entry would otherwise touch the
            // frame after it returns to the allocator (use-after-free
            // aliasing). x86-only effect; no-op on UP / aarch64 / hosted.
            // Remote invalidation and the release are deferred to the batch
            // drain below (Linux `tlb_gather_mmu`).
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
            gather.push((va, pa.0, leaf));
            if gather.len() >= TLB_GATHER_PAGES { drain_gather(&mut gather, &mask); }
        } else if matches!(nonpresent, Some(NonpresentKind::Swap)) {
            // Swap PTEs are non-present and therefore invisible to `translate`.
            // Clear the exact leaf before dropping its slot reference so a fault
            // cannot resurrect a page whose VMA has been zapped.
            if let Some(entry) = clear_current_swap_entry(va) {
                hal::tlb::shootdown_others_va(va, mask.as_words());
                let _ = crate::swap::free_page(entry);
            }
        } else if matches!(nonpresent, Some(NonpresentKind::Marker)) {
            // The marker described contents this zap is discarding; it names
            // no frame and no swap slot, so nothing is released with it.
            if clear_current_pte_marker(va) {
                hal::tlb::shootdown_others_va(va, mask.as_words());
            }
        } else if matches!(nonpresent, Some(NonpresentKind::Migration)) {
            if let Some(marker) = clear_current_migration_entry(va) {
                hal::tlb::shootdown_others_va(va, mask.as_words());
                account_present_removed(va);
                if let Some(pa) = vmm::migration_drop_marker_mapping(marker) {
                    // SAFETY: removing this marker tears down precisely one
                    // original resident PTE reference recorded by its token.
                    unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
                }
            }
        }
        va += step;
    }
    drain_gather(&mut gather, &mask);
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
    // A huge mapping is made of whole huge pages, each covered by one leaf.
    // A request to unmap part of one has no answer — tearing the leaf down
    // removes memory the caller did not name, leaving it removes nothing while
    // the VMA disappears — so the split is refused, exactly as it is in the
    // reference.
    if huge_split_refused(range) {
        return -(Errno::Einval.as_i32() as i64);
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
    let mask = current_mm_cpumask_full();
    // Linux `tlb_gather_mmu`: a range zap batches BOTH the remote invalidation
    // and the frame release, then flushes once and frees. Shooting down per
    // page sent one cross-CPU IPI for every 4 KiB unmapped — a 64 KiB unmap
    // cost sixteen IPI round-trips — and the frame could not be freed until
    // its own shootdown had returned, so the two costs were serialised.
    // The free still happens strictly after the flush that covers its page,
    // which is the invariant the per-page order existed to hold.
    let mut gather: alloc::vec::Vec<(u64, u64, hal::PageSize)> =
        alloc::vec::Vec::with_capacity(TLB_GATHER_PAGES.min(64));
    let mut va = addr;
    let end = range.end;
    while va < end {
        let mut step = PAGE_BYTES;
        // Granule read from the tables, never assumed: a hugetlbfs mapping
        // resolves through one block leaf per huge page.
        #[cfg(feature = "debug-syscost")]
        let walk_started = crate::unmapcost::now_ns();
        let translated = unsafe { unmap_leaf(va) };
        #[cfg(feature = "debug-syscost")]
        crate::unmapcost::walk(walk_started, translated.is_some());
        // Classify all non-present software PTEs with one page-table walk.
        // The individual clear helpers retain their locking/validation, but
        // probing each kind separately made an empty page cost four walks.
        let nonpresent = if translated.is_none() {
            current_nonpresent_kind(va)
        } else {
            None
        };
        if let Some((pa_raw, leaf)) = translated {
            step = leaf.bytes();
            let pa = hal::Pa(pa_raw);
            // SAFETY: `unmap_leaf` cleared and locally invalidated the page;
            // release below is the inverse of demand-page installation.
            // B47: dec_ref + maybe free. Refcount-aware: a frame
            // shared with a forked peer AS (still mapped there via
            // COW) stays alive; only the unconditional free_one_frame
            // path would yank it out from under the peer. dhcpcd's
            // double-fork daemonize triggers this — the launcher's
            // free → munmap → unmap_pte for the if_options heap was
            // freeing pages still mapped in the grandchild's AS,
            // corrupting grandchild's view of the same struct.
            // SMP TLB coherence (`20§5`): flush this VA on every OTHER online
            // CPU BEFORE the frame is freed below, so a peer thread of the
            // same mm can't touch a freed+realloc'd frame through a stale TLB
            // entry. x86-only effect; no-op on UP / aarch64 / hosted.
            // cpumask-targeted (only CPUs that have this mm), not all online.
            // Remote invalidation and the release are deferred to the batch
            // drain below; see `gather` above.
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
            // SAFETY: the leaf was cleared and invalidated everywhere above, so no translation can still reach the frame; a base page goes back through the rmap-aware path and a huge page back to the pool that owns it.
            unsafe { release_leaf_frame(pa.0, leaf); }
            #[cfg(feature = "debug-syscost")]
            let account_started = crate::unmapcost::now_ns();
            account_present_removed(va);
            #[cfg(feature = "debug-syscost")]
            crate::unmapcost::account(account_started);
        } else if matches!(nonpresent, Some(NonpresentKind::Swap)) {
            // `munmap` must release a non-present swap leaf exactly as it
            // releases a present anonymous leaf; otherwise memory.swap.current
            // remains charged after the mapping is gone.
            if let Some(entry) = clear_current_swap_entry(va) {
                hal::tlb::shootdown_others_va(va, mask.as_words());
                let _ = crate::swap::free_page(entry);
            }
        } else if matches!(nonpresent, Some(NonpresentKind::Marker)) {
            // The marker described contents this zap is discarding; it names
            // no frame and no swap slot, so nothing is released with it.
            if clear_current_pte_marker(va) {
                hal::tlb::shootdown_others_va(va, mask.as_words());
            }
        } else if matches!(nonpresent, Some(NonpresentKind::Migration)) {
            if let Some(marker) = clear_current_migration_entry(va) {
                hal::tlb::shootdown_others_va(va, mask.as_words());
                #[cfg(feature = "debug-syscost")]
                let account_started = crate::unmapcost::now_ns();
                account_present_removed(va);
                #[cfg(feature = "debug-syscost")]
                crate::unmapcost::account(account_started);
                if let Some(pa) = vmm::migration_drop_marker_mapping(marker) {
                    // SAFETY: marker removal transfers this original PTE ref.
                    unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
                }
            }
        }
        va += step;
    }
    drain_gather(&mut gather, &mask);

    // VMA bookkeeping side. Post-execve the running CR3 targets
    // cur.mm — that's where the user's VMAs live, not the global
    // boot AS. Mirror glue_mmap so MAP_FIXED's overlap-clear
    // (via glue_munmap) hits the right AS.
    #[cfg(feature = "debug-syscost")]
    let vma_started = crate::unmapcost::now_ns();
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
    #[cfg(feature = "debug-syscost")]
    crate::unmapcost::vma(vma_started);
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
