// Whether a range operation may cut a huge-page mapping where it proposes to.
//
// A hugetlbfs mapping is made of whole huge pages and one page-table leaf
// covers each of them. A request to unmap or discard part of one has no
// answer: tearing the leaf down removes memory the caller did not ask about,
// and leaving it removes nothing while the VMA disappears. The reference
// refuses the split; so does this.

use hal::UserVirtAddr;

use crate::vma::VmaBacking;

use super::AddressSpace;

/// Whether cutting `[start, end)` out of a huge mapping spanning
/// `[vma_start, vma_end)` lands on huge-page boundaries.
///
/// Only the edges INSIDE the mapping matter: a request that starts before the
/// mapping or ends after it does not cut there.
/// # C: O(1)
pub fn huge_split_ok(vma_start: u64, vma_end: u64, huge: u64, start: u64, end: u64) -> bool {
    if huge == 0 { return true; }
    let mask = huge - 1;
    if start > vma_start && (start & mask) != 0 { return false; }
    if end < vma_end && (end & mask) != 0 { return false; }
    true
}

impl AddressSpace {
    /// Whether `[start, end)` cuts any huge mapping off a huge-page boundary.
    /// # C: O(N_vmas in range)
    pub fn huge_split_refused(&self, start: UserVirtAddr, end: u64) -> bool {
        let s = start.as_u64();
        for vma in self.vmas.read().iter() {
            if vma.start.as_u64() >= end { break; }
            if vma.end.as_u64() <= s { continue; }
            let huge = match &vma.backing {
                VmaBacking::File { backing, .. } => backing.huge_page_size(),
                _ => 0,
            };
            if !huge_split_ok(vma.start.as_u64(), vma.end.as_u64(), huge, s, end) { return true; }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const M2: u64 = 2 * 1024 * 1024;
    const BASE: u64 = 0x4000_0000;

    #[test]
    fn a_base_page_mapping_may_be_cut_anywhere() {
        assert!(huge_split_ok(BASE, BASE + 4 * M2, 0, BASE + 4096, BASE + 8192));
    }

    #[test]
    fn a_whole_huge_mapping_may_be_removed() {
        assert!(huge_split_ok(BASE, BASE + 4 * M2, M2, BASE, BASE + 4 * M2));
    }

    #[test]
    fn a_cut_on_huge_boundaries_inside_the_mapping_is_allowed() {
        assert!(huge_split_ok(BASE, BASE + 4 * M2, M2, BASE + M2, BASE + 3 * M2));
    }

    #[test]
    fn a_cut_that_starts_inside_a_huge_page_is_refused() {
        assert!(!huge_split_ok(BASE, BASE + 4 * M2, M2, BASE + 4096, BASE + 2 * M2));
    }

    #[test]
    fn a_cut_that_ends_inside_a_huge_page_is_refused() {
        assert!(!huge_split_ok(BASE, BASE + 4 * M2, M2, BASE, BASE + M2 + 4096));
    }

    #[test]
    fn an_edge_outside_the_mapping_is_not_a_cut() {
        // Starting below and ending above the mapping cuts nothing off a page.
        assert!(huge_split_ok(BASE, BASE + 2 * M2, M2, BASE - 4096, BASE + 2 * M2 + 4096));
    }
}
