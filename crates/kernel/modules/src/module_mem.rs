extern crate alloc;
#[cfg(not(target_os = "oxide-kernel"))]
use alloc::vec::Vec;

use elf::{SHF_EXECINSTR, SHF_WRITE};
use hal::PageFlags;

#[cfg(target_os = "oxide-kernel")]
const PAGE_BYTES: usize = 4096;

/// Translate ELF section flags to final kernel PTE permissions.
/// # C: O(1)
pub fn section_page_flags(sh_flags: u64) -> PageFlags {
    let mut flags = PageFlags::READ;
    if (sh_flags & SHF_WRITE) != 0 { flags |= PageFlags::WRITE; }
    if (sh_flags & SHF_EXECINSTR) != 0 { flags |= PageFlags::EXEC; }
    flags
}

#[cfg(not(target_os = "oxide-kernel"))]
pub struct SectionStorage {
    bytes: Vec<u8>,
}

#[cfg(not(target_os = "oxide-kernel"))]
impl SectionStorage {
    /// Allocate hosted module section storage.
    /// # C: O(size)
    pub fn new(size: usize) -> Option<Self> {
        Some(Self { bytes: alloc::vec![0u8; size] })
    }

    /// Virtual base used for symbol resolution.
    /// # C: O(1)
    pub fn vbase(&self) -> u64 { self.bytes.as_ptr() as u64 }

    /// Section length in bytes.
    /// # C: O(1)
    pub fn len(&self) -> usize { self.bytes.len() }

    /// Immutable section bytes.
    /// # C: O(1)
    pub fn as_slice(&self) -> &[u8] { &self.bytes }

    /// Mutable section bytes before final permissions.
    /// # C: O(1)
    pub fn as_mut_slice(&mut self) -> &mut [u8] { &mut self.bytes }

    /// Hosted tests use heap storage, so final PTE permission work is absent.
    /// # C: O(1)
    pub fn seal(&mut self, _flags: PageFlags) -> bool { true }

    /// Construct hosted storage from bytes for registry tests.
    /// # C: O(size)
    pub fn from_bytes(bytes: Vec<u8>) -> Self { Self { bytes } }
}

#[cfg(target_os = "oxide-kernel")]
mod kernel {
    extern crate alloc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

    #[cfg(target_arch = "aarch64")]
    use hal_aarch64::mmu_ops::ArmMmu;
    #[cfg(target_arch = "x86_64")]
    use hal_x86_64::mmu_ops::X86Mmu;

    use super::PAGE_BYTES;

    const MODULE_VA_BASE: u64 = 0xffff_fc80_0000_0000;
    static MODULE_VA_NEXT: AtomicU64 = AtomicU64::new(MODULE_VA_BASE);

    pub struct SectionStorage {
        pages:  Vec<u64>,
        base:   u64,
        len:    usize,
        sealed: bool,
    }

    impl SectionStorage {
        /// Allocate PMM-backed writable module storage.
        /// # C: O(pages)
        pub fn new(size: usize) -> Option<Self> {
            let n_pages = pages_for(size)?;
            if n_pages == 0 {
                return Some(Self { pages: Vec::new(), base: 0, len: 0, sealed: true });
            }
            let mut pages = Vec::with_capacity(n_pages);
            for _ in 0..n_pages {
                match pmm::setup::alloc_raw_frame() {
                    Some(pa) => pages.push(pa),
                    None => {
                        for pa in pages {
                            // SAFETY: frame was just allocated by alloc_raw_frame and has not been mapped into any visible owner.
                            unsafe { pmm::setup::free_one_frame(pa); }
                        }
                        return None;
                    }
                }
            }
            let base = alloc_va(n_pages)?;
            // SAFETY: pages are freshly allocated raw frames and base is a fresh module VA range.
            unsafe { map_pages(base, &pages, PageFlags::READ | PageFlags::WRITE); }
            Some(Self { pages, base, len: size, sealed: false })
        }

        /// Virtual base used for symbol resolution.
        /// # C: O(1)
        pub fn vbase(&self) -> u64 { self.base }

        /// Section length in bytes.
        /// # C: O(1)
        pub fn len(&self) -> usize { self.len }

        /// Immutable section bytes.
        /// # C: O(1)
        pub fn as_slice(&self) -> &[u8] {
            if self.len == 0 { return &[]; }
            // SAFETY: base maps len bytes of module-owned PMM frames for the SectionStorage lifetime.
            unsafe { core::slice::from_raw_parts(self.base as *const u8, self.len) }
        }

        /// Mutable section bytes before final permissions.
        /// # C: O(1)
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            if self.len == 0 { return &mut []; }
            // SAFETY: loader has exclusive &mut SectionStorage before publication; mapping is writable until seal.
            unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.len) }
        }

        /// Rewrite module pages to final W^X permissions.
        /// # C: O(pages * page-table depth)
        pub fn seal(&mut self, flags: PageFlags) -> bool {
            if self.sealed { return true; }
            if flags.contains(PageFlags::EXEC) {
                arch_irq::cache::sync_icache(self.base, self.len);
            }
            for (i, pa) in self.pages.iter().copied().enumerate() {
                let va = self.base + (i as u64 * PAGE_BYTES as u64);
                // SAFETY: SectionStorage owns this VA range and frame list exclusively during loader finalization.
                unsafe {
                    unmap_page(va);
                    map_page(va, pa, flags);
                }
            }
            self.sealed = true;
            true
        }

        /// Construct storage from bytes for tests compiled against the kernel target.
        /// # C: O(size)
        pub fn from_bytes(bytes: Vec<u8>) -> Self {
            let mut s = Self::new(bytes.len()).expect("module test storage");
            s.as_mut_slice().copy_from_slice(&bytes);
            s
        }
    }

    impl Drop for SectionStorage {
        fn drop(&mut self) {
            if self.base != 0 {
                for i in 0..self.pages.len() {
                    let va = self.base + (i as u64 * PAGE_BYTES as u64);
                    // SAFETY: SectionStorage is dropping its private module VA mappings.
                    unsafe { unmap_page(va); }
                }
            }
            for pa in self.pages.drain(..) {
                // SAFETY: all SectionStorage mappings for this frame were removed immediately above.
                unsafe { pmm::setup::free_one_frame(pa); }
            }
        }
    }

    fn pages_for(size: usize) -> Option<usize> {
        if size == 0 { return Some(0); }
        size.checked_add(PAGE_BYTES - 1).map(|n| n / PAGE_BYTES)
    }

    fn alloc_va(n_pages: usize) -> Option<u64> {
        let bytes = (n_pages as u64).checked_mul(PAGE_BYTES as u64)?;
        Some(MODULE_VA_NEXT.fetch_add(bytes, Ordering::AcqRel))
    }

    unsafe fn map_pages(base: u64, pages: &[u64], flags: PageFlags) {
        for (i, pa) in pages.iter().copied().enumerate() {
            let va = base + (i as u64 * PAGE_BYTES as u64);
            // SAFETY: caller owns each VA/PA pair for this module mapping.
            unsafe { map_page(va, pa, flags); }
        }
    }

    unsafe fn map_page(va: u64, pa: u64, flags: PageFlags) {
        // SAFETY: caller owns this page-aligned module VA and PMM frame.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            <X86Mmu as MmuOps>::map(Va(va), Pa(pa), flags, PageSize::P4K);
            #[cfg(target_arch = "aarch64")]
            <ArmMmu as MmuOps>::map(Va(va), Pa(pa), flags, PageSize::P4K);
        }
    }

    unsafe fn unmap_page(va: u64) {
        // SAFETY: caller owns this page-aligned module VA mapping.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            <X86Mmu as MmuOps>::unmap(Va(va), PageSize::P4K);
            #[cfg(target_arch = "aarch64")]
            <ArmMmu as MmuOps>::unmap(Va(va), PageSize::P4K);
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
pub use kernel::SectionStorage;

#[cfg(test)]
mod tests {
    use super::*;
    use elf::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};

    #[test]
    fn text_sections_are_rx() {
        let _modules = crate::test_serial::claim();
        let f = section_page_flags(SHF_ALLOC | SHF_EXECINSTR);
        assert!(f.contains(PageFlags::READ));
        assert!(f.contains(PageFlags::EXEC));
        assert!(!f.contains(PageFlags::WRITE));
    }

    #[test]
    fn writable_sections_are_non_exec() {
        let _modules = crate::test_serial::claim();
        let f = section_page_flags(SHF_ALLOC | SHF_WRITE);
        assert!(f.contains(PageFlags::READ));
        assert!(f.contains(PageFlags::WRITE));
        assert!(!f.contains(PageFlags::EXEC));
    }
}
