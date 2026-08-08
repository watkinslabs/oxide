// Direct-I/O alignment reporting for the statx `STATX_DIOALIGN` pair.
//
// Ungated so the rule is hosted-testable: reporting an alignment a caller then
// uses to size a direct-I/O buffer is one of the few statx fields a wrong
// answer actually breaks, and it is otherwise only reachable through a mounted
// image.

/// Default memory-buffer alignment for a device that states no stricter
/// constraint. Expressed as the alignment itself, not the mask.
pub const DEFAULT_DIO_MEM_ALIGN: u32 = 512;

/// The `(dio_mem_align, dio_offset_align)` pair for a regular file.
///
/// `inode_constraint` is the inode's own alignment demand when it has one
/// (encrypted or otherwise specially laid-out contents); `1` means "no
/// constraint beyond the device's", which is the ordinary case and the one
/// where the device's own numbers apply: its DMA alignment for the buffer and
/// its logical block size for the offset and length.
///
/// A `logical_block_size` of zero is not a legal device geometry; it is
/// reported as the default rather than propagated, because a zero alignment
/// tells a caller every buffer is acceptable — the most dangerous possible
/// answer. # C: O(1)
pub fn dio_alignment(inode_constraint: u32, logical_block_size: u32) -> (u32, u32) {
    if inode_constraint > 1 { return (inode_constraint, inode_constraint); }
    let off = if logical_block_size == 0 { DEFAULT_DIO_MEM_ALIGN } else { logical_block_size };
    (DEFAULT_DIO_MEM_ALIGN, off)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ordinary case: no inode constraint, so the offset alignment is the
    /// device's logical block size and the buffer alignment is the device's
    /// DMA default. Reporting the two as one number would over-constrain the
    /// buffer on a 4 KiB-sector device. # C: O(1)
    #[test]
    fn unconstrained_inode_reports_the_device_geometry() {
        assert_eq!(dio_alignment(1, 512), (DEFAULT_DIO_MEM_ALIGN, 512));
        assert_eq!(dio_alignment(1, 4096), (DEFAULT_DIO_MEM_ALIGN, 4096));
        assert_eq!(dio_alignment(0, 4096), (DEFAULT_DIO_MEM_ALIGN, 4096));
    }

    /// An inode that demands a stricter alignment overrides BOTH halves — the
    /// buffer must satisfy it too, not just the offset. # C: O(1)
    #[test]
    fn inode_constraint_overrides_both_halves() {
        assert_eq!(dio_alignment(4096, 512), (4096, 4096));
        assert_eq!(dio_alignment(65536, 4096), (65536, 65536));
    }

    /// A zero geometry never reaches the caller as a zero alignment: zero says
    /// "any buffer will do", which is the one answer that cannot be safely
    /// acted on. # C: O(1)
    #[test]
    fn a_zero_geometry_never_reports_a_zero_alignment() {
        let (m, o) = dio_alignment(1, 0);
        assert_ne!(m, 0);
        assert_ne!(o, 0);
        assert_eq!((m, o), (DEFAULT_DIO_MEM_ALIGN, DEFAULT_DIO_MEM_ALIGN));
    }
}
