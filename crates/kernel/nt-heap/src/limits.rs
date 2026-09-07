//! Heap geometry: block/region granularity, growth steps, class thresholds.

/// Data-pointer alignment; every block size is a multiple of it.
pub const BLOCK_ALIGN: usize = 16;
/// Bytes of block header preceding the returned data pointer.
pub const HEADER_BYTES: usize = 8;
/// Reservation/commit granularity inside a subheap region.
pub const REGION_ALIGN: usize = 0x1_0000;
/// Bytes reserved at a region base before its first block header, chosen so
/// the first header lands at `8 mod BLOCK_ALIGN` and every data pointer is
/// `BLOCK_ALIGN`-aligned.
pub const SUBHEAP_OVERHEAD: usize = 4 * BLOCK_ALIGN - HEADER_BYTES;
/// Smallest block: header plus enough body to hold a split remainder.
pub const MIN_BLOCK_BYTES: usize = 3 * BLOCK_ALIGN;
/// Largest block whose size fits the header's block-size field.
pub const MAX_USED_BLOCK_BYTES: usize = 0xffff * BLOCK_ALIGN;
/// At or above this block size an allocation gets its own reserved mapping.
pub const MIN_LARGE_BLOCK_BYTES: usize = MAX_USED_BLOCK_BYTES - 0x1000;
/// Minimum alignment of a region reservation.
pub const REGION_RESERVE_ALIGN: usize = 0x400 * core::mem::size_of::<usize>();
/// First subheap reservation.
pub const INITIAL_SIZE: usize = 0x1_0000;
/// Reservation of the second subheap; doubles per growth up to the cap.
pub const INITIAL_GROW_SIZE: usize = 0x10_0000;
/// Ceiling on the doubling growth step.
pub const MAX_GROW_SIZE: usize = 0xfd_0000;
/// Largest reservation a single subheap may take.
pub const MAX_SUBHEAP_BYTES: usize = 0xffff_0000;

/// Round `value` up to a power-of-two `align`, saturating on overflow.
/// # C: O(1)
pub fn round_up(value: usize, align: usize) -> usize {
    match value.checked_add(align - 1) { Some(sum) => sum & !(align - 1), None => usize::MAX & !(align - 1) }
}

/// Block bytes needed to serve `size` user bytes.
/// # C: O(1)
pub fn block_size_for(size: usize) -> Option<usize> {
    let size = if size < BLOCK_ALIGN { BLOCK_ALIGN } else { size };
    let total = size.checked_add(HEADER_BYTES)?;
    let block = round_up(total, BLOCK_ALIGN);
    if block < size { return None; }
    Some(if block < MIN_BLOCK_BYTES { MIN_BLOCK_BYTES } else { block })
}
