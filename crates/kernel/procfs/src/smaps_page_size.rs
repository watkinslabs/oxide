// Per-VMA page granule reported by `/proc/<pid>/smaps`.

/// Kernel/MMU page size in KiB for one mapping on the supported arches.
/// # C: O(1)
pub(crate) fn for_backing(backing: &vmm::VmaBacking) -> u64 {
    let bytes = match backing {
        vmm::VmaBacking::File { backing, .. } => backing.huge_page_size(),
        _ => 0,
    };
    bytes.max(hal::PAGE_SIZE_BYTES) / 1024
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    const M2: u64 = 2 * 1024 * 1024;

    struct HugeBacking;
    impl vmm::FileBacking for HugeBacking {
        fn read_at(&self, _off: u64, _dst: &mut [u8])
            -> Result<usize, vmm::FileBackingError> { Ok(0) }
        fn size_hint(&self) -> u64 { M2 }
        fn huge_page_size(&self) -> u64 { M2 }
    }

    #[test]
    fn a_hugetlb_vma_reports_its_real_page_granule() {
        let backing = vmm::VmaBacking::File {
            backing: Arc::new(HugeBacking),
            off: 0,
        };
        assert_eq!(for_backing(&backing), 2048);
    }

    #[test]
    fn an_ordinary_vma_reports_the_base_page_granule() {
        assert_eq!(for_backing(&vmm::VmaBacking::Anonymous),
                   hal::PAGE_SIZE_BYTES / 1024);
    }
}
