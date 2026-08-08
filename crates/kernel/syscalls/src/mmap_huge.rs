// The `mmap(2)` huge-page decisions, in an ungated module so hosted tests
// drive them: which granule a request names, what length it really maps, and
// when `MAP_HUGETLB` on a file descriptor is a contradiction.

use pmm::hugetlb::HugePageSize;
use pmm::mmap_flags::MAP_HUGETLB;
use syscall::errno::Errno;

/// What a mapping request means for huge pages.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HugeRequest {
    /// Ordinary base pages.
    None,
    /// Huge pages of this granule.
    Huge(HugePageSize),
}

/// Round a mapping length up to whole huge pages.
///
/// A huge mapping is served by whole leaves, so a length that stops inside one
/// would leave the tail of a leaf covering addresses the mapping does not own.
/// Rounding UP is what the reference does, and it is the only direction that
/// keeps the caller's whole request mapped.
/// # C: O(1)
pub fn huge_len(len: u64, size: HugePageSize) -> Result<u64, Errno> {
    let hb = size.bytes();
    let rounded = len.checked_add(hb - 1).ok_or(Errno::Enomem)?;
    Ok(rounded & !(hb - 1))
}

/// Resolve an ANONYMOUS mapping request's huge-page granule.
///
/// Without `MAP_HUGETLB` the request is for base pages. With it, the size-log
/// field must name a granule this kernel serves; one it does not is `EINVAL`
/// rather than a silent fall back to the default, because a program that asked
/// for 1 GiB pages and got 2 MiB ones has been given the wrong thing.
/// # C: O(1)
pub fn anon_request(flags: u64) -> Result<HugeRequest, Errno> {
    if flags & MAP_HUGETLB == 0 { return Ok(HugeRequest::None); }
    pmm::hugetlb::size_from_flags(flags).map(HugeRequest::Huge).ok_or(Errno::Einval)
}

/// Resolve a FILE-backed mapping request's huge-page granule.
///
/// The file decides, not the flags: mapping a hugetlbfs file gives huge pages
/// whether or not the caller said `MAP_HUGETLB`, and asking for `MAP_HUGETLB`
/// on a file that is not one is a contradiction the reference answers with
/// `EINVAL`.
/// # C: O(1)
pub fn file_request(flags: u64, file_huge_bytes: u64) -> Result<HugeRequest, Errno> {
    if file_huge_bytes != 0 {
        let size = match file_huge_bytes {
            b if b == HugePageSize::Huge2M.bytes() => HugePageSize::Huge2M,
            b if b == HugePageSize::Huge1G.bytes() => HugePageSize::Huge1G,
            _ => return Err(Errno::Einval),
        };
        return Ok(HugeRequest::Huge(size));
    }
    if flags & MAP_HUGETLB != 0 { return Err(Errno::Einval); }
    Ok(HugeRequest::None)
}

impl HugeRequest {
    /// The length this request actually maps.
    /// # C: O(1)
    pub fn len(self, len: u64) -> Result<u64, Errno> {
        match self { HugeRequest::None => Ok(len), HugeRequest::Huge(s) => huge_len(len, s) }
    }
    /// The granule, or `None` for base pages. # C: O(1)
    pub fn size(self) -> Option<HugePageSize> {
        match self { HugeRequest::None => None, HugeRequest::Huge(s) => Some(s) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pmm::mmap_flags::{MAP_ANON, MAP_HUGE_1GB, MAP_HUGE_2MB, MAP_HUGE_SHIFT, MAP_PRIVATE};

    const M2: u64 = 2 * 1024 * 1024;
    const G1: u64 = 1024 * 1024 * 1024;

    #[test]
    fn a_request_without_hugetlb_is_a_base_page_request() {
        assert_eq!(anon_request(MAP_PRIVATE | MAP_ANON), Ok(HugeRequest::None));
        assert_eq!(HugeRequest::None.len(4097), Ok(4097));
    }

    #[test]
    fn hugetlb_with_no_selector_names_the_default_granule() {
        assert_eq!(anon_request(MAP_PRIVATE | MAP_ANON | MAP_HUGETLB),
                   Ok(HugeRequest::Huge(HugePageSize::Huge2M)));
    }

    #[test]
    fn each_selector_names_its_own_granule() {
        assert_eq!(anon_request(MAP_HUGETLB | MAP_HUGE_2MB),
                   Ok(HugeRequest::Huge(HugePageSize::Huge2M)));
        assert_eq!(anon_request(MAP_HUGETLB | MAP_HUGE_1GB),
                   Ok(HugeRequest::Huge(HugePageSize::Huge1G)));
    }

    #[test]
    fn a_granule_this_kernel_does_not_serve_is_einval_not_a_downgrade() {
        assert_eq!(anon_request(MAP_HUGETLB | (16u64 << MAP_HUGE_SHIFT)), Err(Errno::Einval));
    }

    #[test]
    fn a_length_rounds_up_to_whole_huge_pages() {
        assert_eq!(huge_len(1, HugePageSize::Huge2M), Ok(M2));
        assert_eq!(huge_len(M2, HugePageSize::Huge2M), Ok(M2));
        assert_eq!(huge_len(M2 + 1, HugePageSize::Huge2M), Ok(2 * M2));
        assert_eq!(huge_len(1, HugePageSize::Huge1G), Ok(G1));
    }

    #[test]
    fn a_length_that_cannot_be_rounded_is_enomem_not_a_wrap_to_zero() {
        assert_eq!(huge_len(u64::MAX, HugePageSize::Huge2M), Err(Errno::Enomem));
        assert_eq!(huge_len(u64::MAX - 3, HugePageSize::Huge1G), Err(Errno::Enomem));
    }

    #[test]
    fn a_zero_length_stays_zero_and_is_refused_upstream() {
        assert_eq!(huge_len(0, HugePageSize::Huge2M), Ok(0));
    }

    #[test]
    fn mapping_a_hugepage_file_gives_huge_pages_without_the_flag() {
        assert_eq!(file_request(MAP_PRIVATE, M2), Ok(HugeRequest::Huge(HugePageSize::Huge2M)));
        assert_eq!(file_request(MAP_PRIVATE, G1), Ok(HugeRequest::Huge(HugePageSize::Huge1G)));
    }

    #[test]
    fn hugetlb_on_a_file_that_is_not_a_hugepage_file_is_einval() {
        assert_eq!(file_request(MAP_PRIVATE | MAP_HUGETLB, 0), Err(Errno::Einval));
    }

    #[test]
    fn mapping_an_ordinary_file_without_the_flag_is_a_base_page_request() {
        assert_eq!(file_request(MAP_PRIVATE, 0), Ok(HugeRequest::None));
    }

    #[test]
    fn a_file_whose_granule_has_no_leaf_is_refused() {
        assert_eq!(file_request(MAP_PRIVATE, 8192), Err(Errno::Einval));
    }

    #[test]
    fn the_request_reports_the_granule_it_resolved() {
        assert_eq!(HugeRequest::Huge(HugePageSize::Huge1G).size(), Some(HugePageSize::Huge1G));
        assert_eq!(HugeRequest::None.size(), None);
    }
}
