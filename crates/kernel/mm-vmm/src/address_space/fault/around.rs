use hal::{MmuOps, Pa, PageSize, Va, PAGE_SIZE_BYTES};

use crate::vma::{FileBacking, Vma};

use super::super::AddressSpace;

/// Linux's default `fault_around_bytes`: 64 KiB, or 16 base pages on the
/// supported 4 KiB architectures.
const FAULT_AROUND_BYTES: u64 = 64 * 1024;
/// One lowest-level page-table page covers 512 base-page leaves.
const PTE_TABLE_BYTES: u64 = 512 * PAGE_SIZE_BYTES;

fn fault_around_window(
    vma_start: u64,
    vma_end: u64,
    fault_va: u64,
    backing_off: u64,
    file_size: u64,
) -> (u64, u64) {
    let aligned_start = fault_va & !(FAULT_AROUND_BYTES - 1);
    let aligned_end = aligned_start.saturating_add(FAULT_AROUND_BYTES);
    let pte_start = fault_va & !(PTE_TABLE_BYTES - 1);
    let pte_end = pte_start.saturating_add(PTE_TABLE_BYTES);
    let file_pages = file_size.saturating_sub(backing_off)
        .saturating_add(PAGE_SIZE_BYTES - 1) & !(PAGE_SIZE_BYTES - 1);
    let file_end = vma_start.saturating_add(file_pages);
    (
        aligned_start.max(vma_start).max(pte_start),
        aligned_end.min(vma_end).min(pte_end).min(file_end),
    )
}

impl AddressSpace {
    /// Map already-resident file-cache neighbors around a successful read or
    /// execute fault. The window is naturally aligned, VMA/EOF/PTE-table
    /// clamped, and misses are skipped without I/O, matching Linux
    /// `do_fault_around` -> `filemap_map_pages`.
    ///
    /// Every speculative install is read-only even when the VMA is writable:
    /// MAP_PRIVATE must COW and MAP_SHARED must pass through the write-fault
    /// dirtying path before userspace can modify the cache frame.
    /// # SAFETY: `M` names the live page tables and the callbacks own the PMM
    /// PTE-reference transitions for returned backing frames.
    /// # C: O(FAULT_AROUND_BYTES / PAGE_SIZE)
    pub(super) unsafe fn map_file_fault_around<M, DR, IR>(
        &self,
        vma: &Vma,
        fault_va: u64,
        backing: &alloc::sync::Arc<dyn FileBacking>,
        backing_off: u64,
        dec_ref: &mut DR,
        inc_ref: &mut IR,
    )
    where
        M: MmuOps,
        DR: FnMut(u64),
        IR: FnMut(u64),
    {
        let vma_start = vma.start.as_u64();
        let (window_start, window_end) = fault_around_window(
            vma_start, vma.end.as_u64(), fault_va, backing_off, backing.size_hint(),
        );
        if window_start >= window_end { return; }

        let mut flags = vma.prot.to_page_flags();
        flags.remove(hal::PageFlags::WRITE);
        let mut va = window_start;
        while va < window_end {
            if va == fault_va || M::translate(Va(va)).is_some() {
                va += PAGE_SIZE_BYTES;
                continue;
            }
            let file_off = backing_off.saturating_add(va - vma_start);
            let frame = match backing.fault_around_frame(file_off) {
                Ok(Some(frame)) => frame,
                Ok(None) | Err(_) => {
                    va += PAGE_SIZE_BYTES;
                    continue;
                }
            };
            if !frame.map_ref_held { inc_ref(frame.pa); }
            // Revalidate after acquiring the cache reference. The lookup is
            // nonblocking, but a peer fault may have populated this mm.
            if M::translate(Va(va)).is_some() {
                dec_ref(frame.pa);
                va += PAGE_SIZE_BYTES;
                continue;
            }
            // SAFETY: va is page-aligned and inside the cloned VMA; the
            // backing supplied a retained, page-aligned cache frame.
            let replaced = unsafe { M::map(Va(va), Pa(frame.pa), flags, PageSize::P4K) };
            if replaced.is_none() { self.accounting.install_pte(vma); }
            if let Some(old) = replaced {
                hal::tlb::shootdown_others_va(va, self.cpumask());
                dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
            }
            va += PAGE_SIZE_BYTES;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_linux_default_and_one_pte_page() {
        assert_eq!(FAULT_AROUND_BYTES / PAGE_SIZE_BYTES, 16);
        assert_eq!(PTE_TABLE_BYTES / PAGE_SIZE_BYTES, 512);
    }

    #[test]
    fn vma_head_clamp_does_not_extend_the_aligned_window_tail() {
        let (start, end) = fault_around_window(0x123000, 0x150000, 0x127000, 0, 0x40000);
        assert_eq!((start, end), (0x123000, 0x130000));
    }

    #[test]
    fn eof_rounds_up_the_last_partial_page() {
        let (start, end) = fault_around_window(0x200000, 0x220000, 0x204000, 0x3000, 0x7501);
        assert_eq!((start, end), (0x200000, 0x205000));
    }

    #[test]
    fn nonzero_file_offset_at_or_past_eof_produces_an_empty_window() {
        let (start, end) = fault_around_window(0x300000, 0x310000, 0x300000, 0x9000, 0x8000);
        assert!(start >= end);
    }
}
