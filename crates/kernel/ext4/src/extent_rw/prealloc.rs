const SMALL_FILE_MIN_PREALLOC_BLOCKS: u32 = 4;
const MAX_PREALLOC_TAIL_BLOCKS: u32 = 1024;

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
    use super::tail_blocks;

    #[test]
    fn follows_linux_size_windows() {
        assert_eq!(tail_blocks(4096, 0, 0, 1), 3);
        assert_eq!(tail_blocks(4096, 16 * 1024, 4, 1), 3);
        assert_eq!(tail_blocks(4096, 1024 * 1024, 256, 1), 255);
        assert_eq!(tail_blocks(4096, 2 * 1024 * 1024, 512, 1), 0);
        assert_eq!(tail_blocks(4096, 5 * 1024 * 1024, 1280, 1), 0);
    }
}
