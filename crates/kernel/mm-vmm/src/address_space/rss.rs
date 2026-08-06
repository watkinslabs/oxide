// Resident-set arithmetic over the per-mm PTE counters `VmAccounting` already
// maintains at every present↔absent transition. Linux keeps the same numbers
// in `mm->rss_stat[]` (`MM_ANONPAGES`, `MM_FILEPAGES`, `MM_SHMEMPAGES`,
// `MM_SWAPENTS`) and derives RSS from them; nothing here is a second counter,
// only the derivation and the high-water rule.
//
// Kept out of `accounting.rs` because that module is where the atomics live:
// the arithmetic below is what `ru_maxrss`, `/proc/<pid>/status` and
// `/proc/<pid>/statm` all agree on, so it is pure and asserted here.

use crate::vma::VmaBacking;

/// Bytes per resident page. `ru_maxrss` and the `Vm*` rows are KiB.
pub const PAGE_BYTES: u64 = 4096;
const BYTES_PER_KIB: u64 = 1024;

/// The resident page classes of one address space.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RssPages {
    /// Linux `MM_ANONPAGES`.
    pub anon:   u64,
    /// Linux `MM_FILEPAGES` — private and shared file mappings alike.
    pub file:   u64,
    /// Kernel-owned refcounted frames shared into the mapping (vvar, ring
    /// buffers). Linux accounts these as `MM_SHMEMPAGES`-class residency:
    /// they are real pages the process holds down.
    pub shmem:  u64,
    /// Linux `MM_SWAPENTS`. Not resident, so excluded from RSS; carried here
    /// because `/proc/<pid>/status` reports it alongside.
    pub swapents: u64,
}

impl RssPages {
    /// Linux `get_mm_rss` = anon + file + shmem. Swap entries are NOT
    /// resident, and `VM_PFNMAP`/device leaves have no `struct page` to
    /// account, so neither is counted. # C: O(1)
    pub const fn total(&self) -> u64 { self.anon + self.file + self.shmem }

    /// Page count → KiB, the unit of `ru_maxrss` and every `Vm*` row.
    /// # C: O(1)
    pub const fn kib(pages: u64) -> u64 { pages.saturating_mul(PAGE_BYTES / BYTES_PER_KIB) }
}

/// Which `RssPages` member one present leaf moves, decided from the VMA
/// backing alone (Linux `mm_counter`/`mm_counter_file`, which asks the folio
/// the same question). A `PhysRange` leaf is `VM_PFNMAP`-class device memory
/// with no `struct page`, and a `Special` leaf has no frame at all, so neither
/// is resident to anybody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RssClass { Anon, File, Shmem, Device, Untracked }

/// `# C: O(1)`
pub const fn class_of(backing: &VmaBacking) -> RssClass {
    match backing {
        VmaBacking::Anonymous => RssClass::Anon,
        // A private file mapping's COW copy stays file-class until Linux
        // splits it; both it and a shared file page are `MM_FILEPAGES`. A
        // `KernelBytes` VMA is the same shape (a copy of kernel-owned bytes
        // faulted in per page), so it shares the class.
        VmaBacking::File { .. } | VmaBacking::KernelBytes { .. } => RssClass::File,
        VmaBacking::KernelFrame { .. } => RssClass::Shmem,
        VmaBacking::PhysRange { .. } => RssClass::Device,
        VmaBacking::Special => RssClass::Untracked,
    }
}

/// Running per-class tally of leaves an operation installed. `fork` copies the
/// parent's present leaves one at a time and must hand the child a count that
/// matches, or the child under-reports its residency for its whole life.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RssTally {
    pub pages: RssPages,
    pub device: u64,
}

impl RssTally {
    /// # C: O(1)
    pub fn add(&mut self, class: RssClass) {
        match class {
            RssClass::Anon      => self.pages.anon += 1,
            RssClass::File      => self.pages.file += 1,
            RssClass::Shmem     => self.pages.shmem += 1,
            RssClass::Device    => self.device += 1,
            RssClass::Untracked => {}
        }
    }
    /// # C: O(1)
    pub fn add_swap(&mut self) { self.pages.swapents += 1; }
}

/// Linux `get_mm_hiwater_rss` = `max(mm->hiwater_rss, get_mm_rss(mm))`. The
/// latched mark can lag the live total whenever residency grew since the last
/// `update_hiwater_rss`, so a reader must fold both — reporting the latch
/// alone under-reports the peak. # C: O(1)
pub const fn hiwater_rss(latched: u64, live: u64) -> u64 {
    if latched > live { latched } else { live }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_backing_maps_to_the_counter_linux_charges_it_to() {
        assert_eq!(class_of(&VmaBacking::Anonymous), RssClass::Anon);
        assert_eq!(class_of(&VmaBacking::KernelBytes { data: alloc::sync::Arc::from(&[0u8][..]), off: 0 }), RssClass::File);
        assert_eq!(class_of(&VmaBacking::KernelFrame { pa: 0x1000 }), RssClass::Shmem);
        // `VM_PFNMAP` device memory has no `struct page`, so it is nobody's
        // resident set; a `Special` leaf has no frame at all.
        assert_eq!(class_of(&VmaBacking::PhysRange {
            base_pa: 0x1000,
            cache: crate::PhysCacheMode::Device,
        }), RssClass::Device);
        assert_eq!(class_of(&VmaBacking::Special), RssClass::Untracked);
    }

    #[test]
    fn a_tally_routes_each_class_to_its_own_member() {
        let mut t = RssTally::default();
        t.add(RssClass::Anon); t.add(RssClass::Anon);
        t.add(RssClass::File);
        t.add(RssClass::Shmem);
        t.add(RssClass::Device);
        t.add(RssClass::Untracked);
        t.add_swap();
        assert_eq!(t.pages, RssPages { anon: 2, file: 1, shmem: 1, swapents: 1 });
        assert_eq!(t.device, 1);
        // Device leaves and swap entries are not resident; only the three
        // resident classes reach `VmRSS`.
        assert_eq!(t.pages.total(), 4);
    }

    #[test]
    fn resident_set_excludes_swapped_out_pages() {
        let r = RssPages { anon: 10, file: 3, shmem: 2, swapents: 100 };
        assert_eq!(r.total(), 15);
    }

    #[test]
    fn an_empty_address_space_is_zero_resident() {
        assert_eq!(RssPages::default().total(), 0);
    }

    #[test]
    fn pages_convert_to_kib_at_four_kib_per_page() {
        assert_eq!(RssPages::kib(0), 0);
        assert_eq!(RssPages::kib(1), 4);
        assert_eq!(RssPages::kib(256), 1024);
    }

    #[test]
    fn the_high_water_mark_folds_the_live_total_not_just_the_latch() {
        // Latch behind the live total: the live total wins, so a peak reached
        // since the last latch update is still reported.
        assert_eq!(hiwater_rss(5, 9), 9);
        // Live total fallen back after a peak: the latch preserves the peak.
        assert_eq!(hiwater_rss(9, 5), 9);
        assert_eq!(hiwater_rss(0, 0), 0);
    }
}
