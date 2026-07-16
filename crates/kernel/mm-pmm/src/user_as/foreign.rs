use super::*;

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
const PAGE_ALIGN_MASK: u64 = !PAGE_MASK;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

pub unsafe fn read_foreign_user(root_pa: u64, va: u64, dst: &mut [u8]) -> usize {
    let hhdm = hhdm_offset();
    let total = dst.len();
    let mut copied = 0usize;
    while copied < total {
        let cur_va = va + copied as u64;
        let page_off = (cur_va & 0xFFF) as usize;
        let in_page = (4096 - page_off).min(total - copied);
        // SAFETY: root_pa came from a live foreign AS we hold an Arc to; HHDM covers PT memory; reads only.
        let leaf_pa = unsafe {
            read_foreign_leaf_pa(root_pa, cur_va & !0xFFF, hhdm)
        };
        let pa = match leaf_pa { Some(p) => p, None => break };
        // SAFETY: pa is a valid frame from the foreign AS's PT walk;
        // HHDM maps it readable; copy `in_page` bytes from it into
        // dst at offset `copied`.
        unsafe {
            let src = (hhdm + pa + page_off as u64) as *const u8;
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(copied), in_page);
        }
        copied += in_page;
    }
    copied
}

/// Symmetric write helper. Returns bytes written; stops on
/// unmapped or read-only-leaf encountered. Read-only stop is
/// honest (does NOT silently bypass W^X); ptrace POKE relies on
/// this to refuse writing to executable code pages until a real
/// CoW path is wired up.
/// # SAFETY: same as `read_foreign_user`. Writes through HHDM
/// mapping of the leaf PA; caller asserts the leaf is writable
/// (we check `is_leaf_writable` before each chunk).
/// # C: O(src.len())
pub unsafe fn write_foreign_user(root_pa: u64, va: u64, src: &[u8]) -> usize {
    let hhdm = hhdm_offset();
    let total = src.len();
    let mut written = 0usize;
    while written < total {
        let cur_va = va + written as u64;
        let page_off = (cur_va & 0xFFF) as usize;
        let in_page = (4096 - page_off).min(total - written);
        // SAFETY: root_pa came from a live foreign AS we hold an Arc to; HHDM covers PT memory; reads only.
        let leaf = unsafe {
            read_foreign_leaf(root_pa, cur_va & !0xFFF, hhdm)
        };
        let (pa, leaf_raw) = match leaf { Some(t) => t, None => break };
        if !leaf_writable(leaf_raw) { break; }
        // SAFETY: pa from a live foreign AS leaf, writable per check; HHDM gives us a kernel-side writable view.
        unsafe {
            let dst = (hhdm + pa + page_off as u64) as *mut u8;
            core::ptr::copy_nonoverlapping(src.as_ptr().add(written), dst, in_page);
        }
        written += in_page;
    }
    written
}

/// Foreign-root sibling of `unmap::evict_pages_in_range`: drop the
/// physical pages of `[addr, addr+len)` in the address space rooted at
/// `root_pa` (a task OTHER than the running one), keeping its VMAs.
/// process_madvise MADV_DONTNEED/MADV_FREE against a foreign pidfd.
///
/// Frame accounting is kept IDENTICAL to `evict_pages_in_range`: each
/// present leaf is cleared then released via the SAME
/// `crate::setup::rmap_aware_dec_and_maybe_free`, so a COW-shared frame
/// (still mapped in a peer AS) is only unmapped from the target, never
/// freed early. No TLB shootdown is issued — oxide is UP (`smp cpus=0`),
/// the foreign target is not executing, and its TLB is flushed on its
/// next CR3/TTBR reload (`20§5`).
/// # C: O(len/4096) PT walks
pub fn evict_foreign_pages_in_range(root_pa: u64, addr: u64, len: u64) -> i64 {
    use syscall::errno::Errno;
    if addr == 0 || len == 0 || (addr & PAGE_MASK) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let len_aligned = (len + PAGE_MASK) & PAGE_ALIGN_MASK;
    if addr.checked_add(len_aligned).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let hhdm = hhdm_offset();
    let mut va = addr;
    let end = addr + len_aligned;
    while va < end {
        // SAFETY: root_pa is a live foreign AS root the caller pins via
        // Arc and that is NOT active on this UP CPU; HHDM covers PT
        // memory; the leaf slot is exclusively owned (target not running).
        let torn = unsafe {
            #[cfg(target_arch = "x86_64")]
            { hal::pt_walker::unmap_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root_pa, va, hhdm) }
            #[cfg(target_arch = "aarch64")]
            { hal::pt_walker::unmap_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(root_pa, va, hhdm) }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            { let _ = (root_pa, va, hhdm); None::<u64> }
        };
        if let Some(pa) = torn {
            // SAFETY: pa was reachable via the foreign leaf just cleared;
            // rmap_aware_dec_and_maybe_free checks the struct-page refcount
            // and only releases to PMM when the last mapping drops — same
            // contract as the active-root evict path in unmap.rs.
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa); }
        }
        va += PAGE_BYTES;
    }
    0
}

#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn read_foreign_leaf_pa(root_pa: u64, va_aligned: u64, hhdm: u64) -> Option<u64> {
    use hal_x86_64::vmm::PtWalkerX86;
    // SAFETY: root_pa is a valid PML4 frame; HHDM covers PT memory; reads only.
    unsafe { hal::pt_walker::translate_4k_at_root::<PtWalkerX86>(root_pa, va_aligned, hhdm).map(|(pa, _)| pa) }
}
#[cfg(target_arch = "aarch64")]
pub(super) unsafe fn read_foreign_leaf_pa(root_pa: u64, va_aligned: u64, hhdm: u64) -> Option<u64> {
    use hal_aarch64::vmm::PtWalkerArm;
    // SAFETY: root_pa is a valid L0 frame; HHDM covers PT memory; reads only.
    unsafe { hal::pt_walker::translate_4k_at_root::<PtWalkerArm>(root_pa, va_aligned, hhdm).map(|(pa, _)| pa) }
}

#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn read_foreign_leaf(root_pa: u64, va_aligned: u64, hhdm: u64) -> Option<(u64, u64)> {
    use hal_x86_64::vmm::PtWalkerX86;
    // SAFETY: same as read_foreign_leaf_pa; returns leaf raw entry too.
    unsafe { hal::pt_walker::translate_4k_at_root::<PtWalkerX86>(root_pa, va_aligned, hhdm) }
}
#[cfg(target_arch = "aarch64")]
pub(super) unsafe fn read_foreign_leaf(root_pa: u64, va_aligned: u64, hhdm: u64) -> Option<(u64, u64)> {
    use hal_aarch64::vmm::PtWalkerArm;
    // SAFETY: same as read_foreign_leaf_pa; returns leaf raw entry too.
    unsafe { hal::pt_walker::translate_4k_at_root::<PtWalkerArm>(root_pa, va_aligned, hhdm) }
}

#[cfg(target_arch = "x86_64")]
fn leaf_writable(leaf: u64) -> bool {
    // x86_64: PRESENT (bit 0) AND RW (bit 1) AND USER (bit 2).
    (leaf & 0b111) == 0b111
}
#[cfg(target_arch = "aarch64")]
fn leaf_writable(leaf: u64) -> bool {
    // aarch64 stage-1 EL1/EL0: AP[2:1] @ bits [7:6]; AP=01 means
    // EL0/EL1 read-write. Valid (bit 0) + page (bit 1=1 for L3
    // page descriptor) also required.
    let valid = (leaf & 0b11) == 0b11;
    let ap    = (leaf >> 6) & 0b11;
    valid && ap == 0b01
}

/// Per-PTE mprotect helper. After `AddressSpace::mprotect`
/// updates the VMA tree, call this to actually flip the PTE bits
/// for every present 4 KiB leaf in `[va, va+len)` so the live
/// page tables match the new VmaProt. Otherwise a JIT page that
/// was mapped RW and got mprotect'd to R-only is still
/// hardware-writable (or worse, was R-only and got mprotect'd to
/// RWX but stays unwritable, breaking jemalloc/mimalloc).
///
/// Caller passes the AS root_pa (typically `mm.root_pa()`) plus
/// the new `VmaProt`. Issues per-page TLB flush after rewriting
/// each page's leaf.
///
/// # SAFETY: caller asserts (a) `root_pa` is a live AS root the
/// caller has exclusive write access to (per-AS PT lock or UP +
/// preempt-off), (b) `va`/`len` are page-aligned and inside the
/// user range. HHDM-mapped table memory is read/written.
/// # C: O(len/4096 * walk_depth) + per-page TLB flush
pub unsafe fn mprotect_pages(root_pa: u64, va: u64, len: usize, prot: VmaProt) {
    use hal::{MmuOps, PageSize, Va};
    let new_flags = prot.to_page_flags();
    let va_start = va & !0xFFF;
    let va_end = va.checked_add(len as u64).map_or(va_start, |e| (e + 0xFFF) & !0xFFF);
    if va_end <= va_start { return; }
    // Linux `change_protection` + `can_change_pte_writable`: NEVER hardware-
    // upgrade W on a present leaf that currently lacks it — a fork-COW
    // W-stripped frame (anon AND private-file .data/GOT) is still SHARED
    // with the fork peer; granting W here lets stores bypass the COW split
    // and silently corrupt the peer. Keep such leaves W-less: the VMA prot
    // now carries WRITE, so the next store takes the Protection{Write}
    // fault and COW-copies/upgrades per page. Downgrades (removing W,
    // toggling NX) apply directly. Both callers target the CALLER's own
    // active root (mprotect glue passes current mm.root_pa()), so the
    // active-root translate/map primitives — which self-flush per VA —
    // are the correct walkers here.
    let _ = root_pa;
    let mut p = va_start;
    while p < va_end {
        // SAFETY: privileged PT read of the caller's live active root.
        #[cfg(target_arch = "x86_64")]
        let cur = unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::translate(Va(p)) };
        #[cfg(target_arch = "aarch64")]
        let cur = unsafe { <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::translate(Va(p)) };
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let cur: Option<(hal::Pa, hal::PageFlags)> = None;
        if let Some((pa, old_fl)) = cur {
            let mut f = new_flags;
            if f.contains(hal::PageFlags::WRITE) && !old_fl.contains(hal::PageFlags::WRITE) {
                f.remove(hal::PageFlags::WRITE);
            }
            // PROT_NONE (Linux _PAGE_PROTNONE): the leaf must revoke USER
            // access — pack_4k_leaf always sets PRESENT, so keeping USER
            // left PROT_NONE pages readable (guard pages didn't guard).
            // Clearing USER keeps the frame + content resident (a later
            // mprotect(READ) restores access losslessly) while any user
            // touch takes a protection fault → VMA check → SIGSEGV.
            if prot.is_empty() { f.remove(hal::PageFlags::USER); }
            // SAFETY: same-PA permission rewrite on the caller's active root;
            // M::map self-flushes the VA and returns no displaced frame for a
            // same-PA rewrite.
            unsafe {
                #[cfg(target_arch = "x86_64")]
                { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::map(Va(p), hal::Pa(pa.0 & !0xFFF), f, PageSize::P4K); }
                #[cfg(target_arch = "aarch64")]
                { <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::map(Va(p), hal::Pa(pa.0 & !0xFFF), f, PageSize::P4K); }
            }
        }
        p = p.wrapping_add(PAGE_BYTES);
    }
    // SMP TLB coherence (`20§5`): the loops above rewrote PTE permissions
    // (e.g. RELRO RO-downgrade) + flushed only THIS CPU's TLB. Peer threads
    // of the same mm on other CPUs still cache the old (writable) entries;
    // broadcast a remote flush so the new protection is enforced everywhere.
    // x86-only effect (no hardware TLB broadcast); no-op on UP / aarch64 /
    // hosted. No frame is freed here, so a post-loop broadcast is sufficient.
    // Target only the CPUs that have this mm loaded (cpumask), not every
    // online CPU, per Linux flush_tlb_others.
    hal::tlb::shootdown_others_all(current_mm_cpumask());
    let _ = (root_pa, new_flags); // touch on host/test build
}

/// A4-rmap: walk every (root_pa, va) that maps the anonymous frame `pa`,
/// PTE-verified against each target AS. Linux `rmap_walk_anon`: reads
/// `page->mapping` (the AnonVma) + `page->index` (page offset within the
/// originating VMA) from `PageMeta`, enumerates the family's chain
/// edges, computes each candidate VA, and CONFIRMS the leaf actually
/// maps `pa` before yielding — chain edges can be stale (a peer unmapped
/// locally without pruning) so the PTE check is authoritative. Invokes
/// `f(root_pa, va)` per confirmed mapper and returns the count, which
/// equals `PageMeta.mapcount(pa)` once the chain is complete (the parent
/// self-edge from `AddressSpace::mmap` + child edges from
/// `fork_cow_pages`). The runtime "who maps this page" oracle for
/// migration / pageout and the COW-reuse cross-check.
/// # C: O(N_chain_edges) page-table walks
pub fn rmap_walk_anon_pa<F: FnMut(u64, u64)>(pa: u64, mut f: F) -> usize {
    let av = match crate::setup::anon_vma_for_pa(pa) { Some(a) => a, None => return 0 };
    let idx = crate::setup::page_index_for_pa(pa) as u64;
    let hhdm = hhdm_offset();
    let target = pa & PAGE_ALIGN_MASK;
    let mut count = 0usize;
    av.walk(|mm, start, end| {
        let va = start.saturating_add(idx.saturating_mul(4096));
        if va >= end { return; }
        let root = mm.root_pa();
        if root == 0 { return; }
        // SAFETY: root comes from a live rmap target; HHDM covers page-table memory.
        let mapped = unsafe { read_foreign_leaf_pa(root, va & PAGE_ALIGN_MASK, hhdm) };
        if mapped.map(|p| p & PAGE_ALIGN_MASK) == Some(target) {
            f(root, va);
            count += 1;
        }
    });
    count
}
