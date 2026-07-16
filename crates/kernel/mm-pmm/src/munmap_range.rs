use hal::{UserVirtAddr, USER_VA_END};
use syscall::errno::Errno;

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
const PAGE_ALIGN_MASK: u64 = !PAGE_MASK;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MunmapRange {
    pub start: UserVirtAddr,
    pub len_aligned: usize,
    pub end: u64,
}

/// Linux `do_vmi_munmap` admission: aligned start, bounded raw length,
/// then page-align length and reject empty/wrapped ranges.
/// # C: O(1)
pub fn validate_munmap_range(addr: u64, len: u64) -> Result<MunmapRange, i64> {
    let einval = -(Errno::Einval.as_i32() as i64);
    if (addr & PAGE_MASK) != 0 || addr > USER_VA_END {
        return Err(einval);
    }
    if len > USER_VA_END - addr {
        return Err(einval);
    }
    let len_aligned = (len + PAGE_MASK) & PAGE_ALIGN_MASK;
    let end = addr + len_aligned;
    if end == addr || len_aligned > usize::MAX as u64 {
        return Err(einval);
    }
    let start = match UserVirtAddr::new(addr) {
        Some(u) => u,
        None    => return Err(einval),
    };
    Ok(MunmapRange { start, len_aligned: len_aligned as usize, end })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

    #[test]
    fn munmap_validation_rejects_unaligned_start() {
        assert_eq!(validate_munmap_range(0x1001, 0x1000).unwrap_err(), einval());
    }

    #[test]
    fn munmap_validation_rejects_empty_range() {
        assert_eq!(validate_munmap_range(0x1000, 0).unwrap_err(), einval());
    }

    #[test]
    fn munmap_validation_rejects_len_past_user_end_before_rounding() {
        assert_eq!(validate_munmap_range(USER_VA_END - 0x1000, 0x1001).unwrap_err(), einval());
    }

    #[test]
    fn munmap_validation_accepts_zero_start_and_rounds_len() {
        let r = validate_munmap_range(0, 1).unwrap();
        assert_eq!(r.start.as_u64(), 0);
        assert_eq!(r.len_aligned, 0x1000);
        assert_eq!(r.end, 0x1000);
    }

    #[test]
    fn munmap_validation_accepts_exclusive_user_end() {
        let r = validate_munmap_range(USER_VA_END - 0x1000, 1).unwrap();
        assert_eq!(r.end, USER_VA_END);
    }
}
