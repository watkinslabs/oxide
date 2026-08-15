//! How large a loop device is, and whether a block size is legal.
//!
//! Both are pure functions of the backing file's size and the configured
//! window, so both are decided here and tested without a device.

use syscall::errno::Errno;

/// Sector size the capacity is reported in, always, regardless of the logical
/// block size the device advertises.
pub const SECTOR_BYTES: u64 = 512;

/// Smallest and largest logical block size a loop device may be given.
pub const MIN_BLOCK_SIZE: u32 = 512;
pub const MAX_BLOCK_SIZE: u32 = 4096;

/// Usable bytes of a backing file `file_bytes` long through the window
/// `offset` / `sizelimit`.
///
/// An offset past the end yields zero rather than an error — the reference
/// calls that weird but possible and reports an empty device. A `sizelimit` of
/// zero means "to the end"; a limit larger than what remains does not extend
/// the device past the file.
/// # C: O(1)
pub fn usable_bytes(file_bytes: u64, offset: u64, sizelimit: u64) -> u64 {
    let remaining = file_bytes.saturating_sub(offset);
    if sizelimit != 0 && sizelimit < remaining { sizelimit } else { remaining }
}

/// Capacity in 512-byte sectors, which is the unit the block layer and every
/// size ioctl report. A trailing partial sector is not addressable and is
/// therefore not counted. # C: O(1)
pub fn capacity_sectors(file_bytes: u64, offset: u64, sizelimit: u64) -> u64 {
    usable_bytes(file_bytes, offset, sizelimit) / SECTOR_BYTES
}

/// A logical block size is legal iff it is a power of two within the
/// supported range. Anything else is `EINVAL`. # C: O(1)
pub fn validate_block_size(bsize: u32) -> Result<u32, Errno> {
    if bsize < MIN_BLOCK_SIZE || bsize > MAX_BLOCK_SIZE || !bsize.is_power_of_two() {
        return Err(Errno::Einval);
    }
    Ok(bsize)
}

/// Byte offset in the backing file for a device-relative byte offset, or
/// `None` when the access leaves the configured window. The window is what
/// makes a loop device over a partition image safe: an access past
/// `sizelimit` must not reach the bytes that follow it in the file.
/// # C: O(1)
pub fn backing_offset(offset: u64, sizelimit: u64, file_bytes: u64,
                      pos: u64, len: u64) -> Option<u64> {
    let usable = usable_bytes(file_bytes, offset, sizelimit);
    let end = pos.checked_add(len)?;
    if end > usable { return None; }
    offset.checked_add(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No window: the whole file, rounded down to whole sectors.
    #[test]
    fn an_unwindowed_device_is_the_whole_file() {
        assert_eq!(usable_bytes(4096, 0, 0), 4096);
        assert_eq!(capacity_sectors(4096, 0, 0), 8);
        // A trailing partial sector is not addressable.
        assert_eq!(capacity_sectors(4096 + 100, 0, 0), 8);
    }

    /// An offset shortens the device; an offset past the end empties it rather
    /// than wrapping or erroring.
    #[test]
    fn an_offset_shortens_the_device_and_never_wraps() {
        assert_eq!(usable_bytes(4096, 1024, 0), 3072);
        assert_eq!(usable_bytes(4096, 4096, 0), 0);
        assert_eq!(usable_bytes(4096, 9999, 0), 0);
        assert_eq!(capacity_sectors(4096, 9999, 0), 0);
    }

    /// A size limit caps the device, but cannot extend it past the file.
    #[test]
    fn a_size_limit_caps_but_never_extends() {
        assert_eq!(usable_bytes(4096, 0, 1024), 1024);
        assert_eq!(usable_bytes(4096, 0, 8192), 4096, "a limit past the end is not an extension");
        assert_eq!(usable_bytes(4096, 1024, 8192), 3072);
        assert_eq!(usable_bytes(4096, 1024, 512), 512);
    }

    /// The property the window exists for: no access may reach a byte outside
    /// it. A loop device over one partition of an image must not be able to
    /// read the next partition.
    #[test]
    fn an_access_past_the_window_is_refused() {
        // 4 KiB file, window = [1024, 1024+512)
        assert_eq!(backing_offset(1024, 512, 4096, 0, 512), Some(1024));
        assert_eq!(backing_offset(1024, 512, 4096, 511, 1), Some(1535));
        assert_eq!(backing_offset(1024, 512, 4096, 512, 1), None, "past the size limit");
        assert_eq!(backing_offset(1024, 512, 4096, 0, 513), None, "straddles the end");
        assert_eq!(backing_offset(1024, 0, 4096, 3072, 1), None, "past the file");
        assert_eq!(backing_offset(1024, 0, 4096, u64::MAX, 1), None, "overflow is refused");
    }

    #[test]
    fn block_sizes_outside_the_range_or_not_a_power_of_two_are_refused() {
        for good in [512u32, 1024, 2048, 4096] { assert_eq!(validate_block_size(good), Ok(good)); }
        for bad in [0u32, 1, 256, 511, 513, 1536, 8192, u32::MAX] {
            assert_eq!(validate_block_size(bad), Err(Errno::Einval), "{bad}");
        }
    }
}
