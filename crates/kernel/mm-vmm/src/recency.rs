// `vma_has_recency` — the reclaim/access-marking recency predicate
// consulted before a resident page's access is counted toward LRU
// promotion. Ungated (no target gate, no crate boundary) so the hosted
// suite can pin the decision directly.
//
// Two Linux inputs fold in:
//   - `vma->vm_flags & (VM_SEQ_READ | VM_RAND_READ)` — a madvise(2) hint
//     that reads through this range should not bias reclaim aging.
//   - `vma->vm_file && vma->vm_file->f_mode & FMODE_NOREUSE` — a
//     fadvise64(2) `POSIX_FADV_NOREUSE` hint on the mapped file.
//
// Either one suppresses recency. `noreuse` is the caller's
// `backing.noreuse()` read (false for anonymous/no-file backings, exactly
// Linux's `vma->vm_file == NULL` short-circuit).

use crate::vma::VmaFlags;

/// True when a resident page touched through this VMA should be promoted
/// (marked referenced / activated) on access; false when reclaim should
/// leave it exactly where it is. # C: O(1)
pub fn vma_has_recency(flags: VmaFlags, noreuse: bool) -> bool {
    if flags.intersects(VmaFlags::SEQ_READ | VmaFlags::RAND_READ) { return false; }
    if noreuse { return false; }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default VMA (no madvise hint, no NOREUSE file) has recency —
    /// the common case where access-driven LRU promotion applies. # C: O(1)
    #[test]
    fn default_vma_has_recency() {
        assert!(vma_has_recency(VmaFlags::empty(), false));
    }

    /// A NOREUSE file suppresses recency regardless of VMA flags. # C: O(1)
    #[test]
    fn noreuse_file_has_no_recency() {
        assert!(!vma_has_recency(VmaFlags::empty(), true));
        assert!(!vma_has_recency(VmaFlags::SHARED, true));
    }

    /// MADV_SEQUENTIAL / MADV_RANDOM each independently suppress recency,
    /// with no file involved. # C: O(1)
    #[test]
    fn seq_or_rand_read_suppresses_recency_without_noreuse() {
        assert!(!vma_has_recency(VmaFlags::SEQ_READ, false));
        assert!(!vma_has_recency(VmaFlags::RAND_READ, false));
        assert!(!vma_has_recency(VmaFlags::SEQ_READ | VmaFlags::RAND_READ, false));
    }

    /// Other, unrelated VMA flags do not affect recency on their own. # C: O(1)
    #[test]
    fn unrelated_flags_do_not_suppress_recency() {
        assert!(vma_has_recency(VmaFlags::SHARED | VmaFlags::LOCKED, false));
    }

    /// A NOREUSE file AND a madvise hint together still suppress — the
    /// predicate is an OR of the two suppressors, matching the reference's
    /// two independent `if` returns rather than requiring both. # C: O(1)
    #[test]
    fn noreuse_and_seq_read_together_suppress_recency() {
        assert!(!vma_has_recency(VmaFlags::SEQ_READ, true));
    }
}
