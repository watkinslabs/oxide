// Decision logic for the Linux contracts the block shim stands in for: who owns a request once its
// completion callback has run, how many bytes a page can lend a bio, and whether releasing a gendisk
// still owes the block registry an unregister. No target gate — every rule here is unit tested.
use super::types::{RQ_END_IO_FREE, RQ_END_IO_NONE};

/// Ownership of a request after `blk_mq_end_request` has run its completion callback.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(super) enum RqOwner {
    /// Completion path owes the free: no callback was installed, or it returned `RQ_END_IO_FREE`.
    FreeHere,
    /// Callback returned `RQ_END_IO_NONE` and kept the request; it must not be touched again here.
    Callback,
}

/// Who frees a request once its `rq_end_io_fn` returned `ret` (`None` = no callback installed).
/// Either answer forbids dereferencing the request afterwards except through the free path.
/// # C: O(1)
pub(super) fn rq_owner_after_end_io(ret: Option<i32>) -> RqOwner {
    match ret {
        None => RqOwner::FreeHere,
        Some(RQ_END_IO_FREE) => RqOwner::FreeHere,
        Some(RQ_END_IO_NONE) => RqOwner::Callback,
        // An out-of-range return is not RQ_END_IO_FREE, so the conservative reading is that the
        // callback kept the request: freeing on an unrecognised value would risk a double free.
        Some(_) => RqOwner::Callback,
    }
}

/// Bytes a `[off, off + len)` request may take from a region of `region_len` bytes.
/// Linux's bio_add_page is all-or-nothing: it adds the whole `len` or reports zero bytes added.
/// # C: O(1)
pub(super) fn addable_bytes(region_len: usize, off: usize, len: usize) -> usize {
    if len == 0 { return 0; }
    if off > region_len { return 0; }
    if len > region_len - off { return 0; }
    len
}

/// Whether releasing a gendisk still owes the block registry an unregister for its name.
/// `registered` is the gendisk's publication flag, which `del_gendisk` clears.
/// # C: O(1)
pub(super) fn release_needs_unregister(registered: u32, name_len: usize) -> bool {
    registered != 0 && name_len != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_4K: usize = 4096;
    const HUGE_LEN: usize = 1 << 20;

    #[test]
    fn no_end_io_callback_leaves_the_free_to_the_completion_path() {
        assert_eq!(rq_owner_after_end_io(None), RqOwner::FreeHere);
    }

    #[test]
    fn end_io_free_means_the_completion_path_frees_the_request() {
        assert_eq!(rq_owner_after_end_io(Some(RQ_END_IO_FREE)), RqOwner::FreeHere);
    }

    #[test]
    fn end_io_none_means_the_callback_kept_the_request() {
        assert_eq!(rq_owner_after_end_io(Some(RQ_END_IO_NONE)), RqOwner::Callback);
    }

    #[test]
    fn unrecognised_end_io_return_never_frees() {
        for ret in [-1, 2, 7, i32::MAX, i32::MIN] {
            assert_eq!(rq_owner_after_end_io(Some(ret)), RqOwner::Callback, "ret={ret}");
        }
    }

    #[test]
    fn a_page_lends_at_most_its_own_tail() {
        assert_eq!(addable_bytes(PAGE_4K, 0, PAGE_4K), PAGE_4K);
        assert_eq!(addable_bytes(PAGE_4K, 512, PAGE_4K - 512), PAGE_4K - 512);
        assert_eq!(addable_bytes(PAGE_4K, PAGE_4K, 0), 0);
    }

    #[test]
    fn a_length_past_the_page_end_adds_nothing() {
        assert_eq!(addable_bytes(PAGE_4K, 0, PAGE_4K + 1), 0);
        assert_eq!(addable_bytes(PAGE_4K, 512, PAGE_4K), 0);
        assert_eq!(addable_bytes(PAGE_4K, 0, HUGE_LEN), 0);
    }

    #[test]
    fn an_offset_past_the_page_end_adds_nothing() {
        assert_eq!(addable_bytes(PAGE_4K, PAGE_4K + 1, 1), 0);
        assert_eq!(addable_bytes(PAGE_4K, HUGE_LEN, 1), 0);
        assert_eq!(addable_bytes(0, 1, 1), 0);
    }

    #[test]
    fn a_zero_length_add_is_rejected_like_linux() {
        assert_eq!(addable_bytes(PAGE_4K, 0, 0), 0);
    }

    #[test]
    fn the_bound_is_never_a_partial_count() {
        for len in [1usize, 511, 4095, 4096, 4097, 8192] {
            let got = addable_bytes(PAGE_4K, 0, len);
            assert!(got == len || got == 0, "len={len} got={got}");
        }
    }

    #[test]
    fn releasing_a_published_disk_still_owes_an_unregister() {
        assert!(release_needs_unregister(1, 5));
    }

    #[test]
    fn releasing_an_unpublished_or_unnamed_disk_owes_nothing() {
        assert!(!release_needs_unregister(0, 5));
        assert!(!release_needs_unregister(1, 0));
        assert!(!release_needs_unregister(0, 0));
    }
}
