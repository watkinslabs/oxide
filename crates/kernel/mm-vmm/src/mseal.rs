// mseal(2) argument ladder.
//
// NOT target-gated: `462_mseal.rs` is `#![cfg(target_os = "oxide-kernel")]`, so
// a test written there never compiles. Every EINVAL-vs-ENOMEM decision lives
// here; the slot only fetches the mm and applies the seal.
//
// Which operations a sealed VMA then rejects (all `-EPERM`):
//   munmap / MAP_FIXED overlap-clear
//   mprotect / pkey_mprotect
//   mremap, either end
//   destructive madvise
// Nothing else is blocked, and there is no unseal.

use crate::Error;

/// Page-align `len_in`; `Err(Inval)` when a non-zero length rounds up to
/// zero. `mbind(2)` tolerates that wrap (it becomes a zero-length no-op);
/// `mseal(2)` does not, because silently sealing nothing would be a security
/// answer the caller did not ask for.
/// # C: O(1)
fn mseal_len(len_in: u64) -> Result<u64, Error> {
    let len = len_in.wrapping_add(hal::PAGE_SIZE_BYTES - 1) & !(hal::PAGE_SIZE_BYTES - 1);
    if len_in != 0 && len == 0 { return Err(Error::Inval); }
    Ok(len)
}

/// mseal(2)'s validation, in order. `Ok(None)` is the `end == start` early
/// success — a zero-length mseal seals nothing and returns 0, NOT ENOMEM.
///
/// Every failure here is EINVAL; ENOMEM belongs exclusively to the
/// "range contains unmapped memory" test the caller runs afterwards, and
/// conflating the two would let a caller mistake a rejected argument for an
/// unmapped range.
/// # C: O(1)
pub fn mseal_args(start: u64, len_in: u64, flags: u64) -> Result<Option<(u64, u64)>, Error> {
    if flags != 0 { return Err(Error::Inval); }
    if start & (hal::PAGE_SIZE_BYTES - 1) != 0 { return Err(Error::Inval); }
    let len = mseal_len(len_in)?;
    let end = start.wrapping_add(len);
    if end < start { return Err(Error::Inval); }
    if end == start { return Ok(None); }
    Ok(Some((start, end)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    const PAGE: u64 = 0x1000;

    #[test]
    fn any_flag_bit_is_einval_before_the_address_is_looked_at() {
        // Unaligned start AND a flag: the flag check runs first, but both are
        // EINVAL so the test that matters is that a flag alone fails.
        assert_eq!(mseal_args(0x4000_0000, PAGE, 1), Err(Error::Inval));
        assert_eq!(mseal_args(0x4000_0000, PAGE, 1 << 63), Err(Error::Inval));
        assert!(mseal_args(0x4000_0000, PAGE, 0).is_ok());
    }

    #[test]
    fn unaligned_start_is_einval_not_enomem() {
        assert_eq!(mseal_args(0x4000_0001, PAGE, 0), Err(Error::Inval));
        assert_eq!(mseal_args(0x4000_0fff, PAGE, 0), Err(Error::Inval));
    }

    #[test]
    fn len_is_rounded_up_to_a_whole_page() {
        // mseal(addr, 1) seals ONE page — the old shim required a page-aligned
        // len and answered EINVAL here.
        assert_eq!(mseal_args(0x4000_0000, 1, 0), Ok(Some((0x4000_0000, 0x4000_1000))));
        assert_eq!(mseal_args(0x4000_0000, PAGE + 1, 0),
                   Ok(Some((0x4000_0000, 0x4000_2000))));
    }

    #[test]
    fn zero_length_succeeds_without_sealing_anything() {
        // `end == start` returns 0. The old shim reached seal_range, which
        // rejected start >= end and reported ENOMEM.
        assert_eq!(mseal_args(0x4000_0000, 0, 0), Ok(None));
    }

    #[test]
    fn a_length_that_rounds_up_to_zero_is_einval() {
        assert_eq!(mseal_args(0x4000_0000, u64::MAX, 0), Err(Error::Inval));
        assert_eq!(mseal_args(0x4000_0000, u64::MAX - 100, 0), Err(Error::Inval));
    }

    #[test]
    fn an_end_that_wraps_past_the_top_of_the_address_space_is_einval() {
        // len rounds cleanly, but start + len wraps.
        let start = 0xffff_ffff_ffff_0000u64;
        assert_eq!(mseal_args(start, 0x2_0000, 0), Err(Error::Inval));
    }
}
