// remap_file_pages(2) slot 216 — argument admission for Linux's DEPRECATED
// emulation (`mm/mmap.c` SYSCALL_DEFINE5(remap_file_pages)).
//
// The nonlinear-VMA implementation this call once had is gone from Linux: the
// syscall now re-`do_mmap`s the same file over the same address with
// MAP_SHARED|MAP_FIXED|MAP_POPULATE and the caller's new `pgoff`. What survives
// verbatim is the argument ladder, and its order is the only observable part of
// a rejected call — so it lives outside the kernel-gated slot file where the
// hosted suite can assert it (CLAUDE.md phantom-test rule, docs/53).
//
//   prot != 0                              -> EINVAL   (prot is REJECTED, not applied)
//   start &= PAGE_MASK; size &= PAGE_MASK
//   start + size <= start                  -> EINVAL   (zero size, or wrap)
//   pgoff + (size >> PAGE_SHIFT) < pgoff   -> EINVAL   (pgoff wrap)

use syscall::errno::Errno;

/// Aligned `(start, size)` a validated `remap_file_pages` call operates on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RemapRange { pub start: u64, pub size: u64 }

/// The pre-VMA half of Linux's ladder. `page_size` is the caller's base page
/// (both arches use 4 KiB, but the mask is derived rather than assumed so the
/// truncate-then-check order is testable on its own).
///
/// `prot` is rejected outright when nonzero: modern Linux takes the protection
/// from the existing VMA and refuses to let this call change it. Silently
/// ignoring a nonzero `prot` would hand back a mapping with permissions the
/// caller did not ask for.
/// # C: O(1)
pub fn remap_check(prot: u64, start: u64, size: u64, pgoff: u64, page_size: u64)
    -> Result<RemapRange, Errno>
{
    if prot != 0 { return Err(Errno::Einval); }
    let mask = !(page_size - 1);
    let start = start & mask;
    let size = size & mask;
    // Truncation happens FIRST, so a sub-page `size` becomes 0 and is rejected
    // here rather than mapping a whole page the caller never asked for.
    if start.checked_add(size).is_none_or(|e| e <= start) { return Err(Errno::Einval); }
    let pages = size / page_size;
    if pgoff.checked_add(pages).is_none() { return Err(Errno::Einval); }
    Ok(RemapRange { start, size })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;

    /// A nonzero `prot` is EINVAL before anything else is examined — including
    /// arguments that are themselves invalid, so the caller learns which rule
    /// it broke first. # C: O(1)
    #[test]
    fn nonzero_prot_is_rejected_first() {
        assert_eq!(remap_check(1, PAGE, PAGE, 0, PAGE), Err(Errno::Einval));
        assert_eq!(remap_check(7, 0, 0, 0, PAGE), Err(Errno::Einval));
        assert_eq!(remap_check(u64::MAX, PAGE, PAGE, 0, PAGE), Err(Errno::Einval));
    }

    /// `start` and `size` are truncated DOWN to the page, not rounded up.
    /// # C: O(1)
    #[test]
    fn start_and_size_truncate_down() {
        assert_eq!(remap_check(0, PAGE + 1, 2 * PAGE + 4095, 0, PAGE),
            Ok(RemapRange { start: PAGE, size: 2 * PAGE }));
    }

    /// A size below one page truncates to zero and is EINVAL — the
    /// `start + size <= start` arm. Rounding up instead would remap a page the
    /// caller never named. # C: O(1)
    #[test]
    fn sub_page_size_becomes_zero_and_is_einval() {
        assert_eq!(remap_check(0, PAGE, 1, 0, PAGE), Err(Errno::Einval));
        assert_eq!(remap_check(0, PAGE, PAGE - 1, 0, PAGE), Err(Errno::Einval));
        assert_eq!(remap_check(0, PAGE, 0, 0, PAGE), Err(Errno::Einval));
    }

    /// `start + size` wrapping past the top of the address space is EINVAL, not
    /// a tiny range at address 0. # C: O(1)
    #[test]
    fn address_wrap_is_einval() {
        let top = u64::MAX & !(PAGE - 1);
        assert_eq!(remap_check(0, top, PAGE, 0, PAGE), Err(Errno::Einval));
        assert_eq!(remap_check(0, top - PAGE, 4 * PAGE, 0, PAGE), Err(Errno::Einval));
    }

    /// A `pgoff` that would wrap when the request's page count is added is
    /// EINVAL — the check Linux spells `pgoff + (size >> PAGE_SHIFT) < pgoff`.
    /// # C: O(1)
    #[test]
    fn pgoff_wrap_is_einval() {
        assert_eq!(remap_check(0, PAGE, 2 * PAGE, u64::MAX - 1, PAGE), Err(Errno::Einval));
        assert_eq!(remap_check(0, PAGE, 2 * PAGE, u64::MAX - 2, PAGE),
            Ok(RemapRange { start: PAGE, size: 2 * PAGE }));
    }

    /// A well-formed call passes through with the aligned range. # C: O(1)
    #[test]
    fn well_formed_call_is_accepted() {
        assert_eq!(remap_check(0, 0x4000_0000, 4 * PAGE, 17, PAGE),
            Ok(RemapRange { start: 0x4000_0000, size: 4 * PAGE }));
    }

    /// A 64 KiB base page truncates more aggressively; the ladder is expressed
    /// against the caller's page size rather than a hardcoded 4 KiB. # C: O(1)
    #[test]
    fn ladder_follows_the_given_page_size() {
        const P64: u64 = 65536;
        assert_eq!(remap_check(0, P64 + 4096, P64 + 4096, 0, P64),
            Ok(RemapRange { start: P64, size: P64 }));
        assert_eq!(remap_check(0, P64, 4096, 0, P64), Err(Errno::Einval));
    }
}
