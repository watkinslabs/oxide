const SMALL_FILE_MIN_PREALLOC_BLOCKS: u32 = 4;
const MAX_PREALLOC_TAIL_BLOCKS: u32 = 1024;
const GROUP_PREALLOC_TARGET_BYTES: u64 = 2 * 1024 * 1024;
const GROUP_PREALLOC_MIN_BLOCKS: u64 = 32;

/// Size the shared locality reservation from the filesystem geometry. Linux
/// targets 2 MiB, keeps at least 32 allocation units, and rounds to a RAID
/// stripe so the shared tail does not split a stripe.
pub(super) fn group_prealloc_blocks(block_size: u64, stripe: u32) -> u32 {
    if block_size == 0 { return 0; }
    let base = (GROUP_PREALLOC_TARGET_BYTES / block_size).max(GROUP_PREALLOC_MIN_BLOCKS);
    let stripe = u64::from(stripe);
    let rounded = if stripe > 1 {
        base.saturating_add(stripe - 1) / stripe * stripe
    } else { base };
    rounded.min(u64::from(u32::MAX)) as u32
}

/// Size a regular-file data reservation using Linux's file-size windows.
/// # C: O(1)
pub(super) fn tail_blocks(block_size: u64, current_size: u64, logical_start: u32, count: u32) -> u32 {
    let request_end = u64::from(logical_start).saturating_add(u64::from(count));
    let file_blocks = current_size.saturating_add(block_size.saturating_sub(1)) / block_size;
    let end_blocks = file_blocks.max(request_end);
    let bytes = end_blocks.saturating_mul(block_size);
    let target = if bytes <= 1024 * 1024 {
        let min_blocks = (16 * 1024 / block_size).max(u64::from(SMALL_FILE_MIN_PREALLOC_BLOCKS));
        end_blocks.max(min_blocks).next_power_of_two()
    } else if bytes <= 4 * 1024 * 1024 {
        2 * 1024 * 1024 / block_size
    } else if bytes <= 8 * 1024 * 1024 {
        4 * 1024 * 1024 / block_size
    } else {
        8 * 1024 * 1024 / block_size
    };
    target.max(request_end).saturating_sub(request_end)
        .min(u64::from(MAX_PREALLOC_TAIL_BLOCKS)) as u32
}

#[cfg(test)]
mod tests {
    use super::{group_prealloc_blocks, tail_blocks};

    #[test]
    fn group_preallocation_uses_geometry_and_stripe() {
        assert_eq!(group_prealloc_blocks(4096, 0), 512);
        assert_eq!(group_prealloc_blocks(2048, 0), 1024);
        assert_eq!(group_prealloc_blocks(4096, 768), 768);
        assert_eq!(group_prealloc_blocks(65536, 0), 32);
    }

    #[test]
    fn follows_linux_size_windows() {
        assert_eq!(tail_blocks(4096, 0, 0, 1), 3);
        assert_eq!(tail_blocks(4096, 16 * 1024, 4, 1), 3);
        assert_eq!(tail_blocks(4096, 1024 * 1024, 256, 1), 255);
        assert_eq!(tail_blocks(4096, 2 * 1024 * 1024, 512, 1), 0);
        assert_eq!(tail_blocks(4096, 5 * 1024 * 1024, 1280, 1), 0);
    }
}
