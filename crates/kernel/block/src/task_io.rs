// Charge block I/O to the task that asked for it, feeding `ru_inblock` /
// `ru_oublock` and `/proc/<pid>/io`'s `read_bytes` / `write_bytes`.
//
// Charged at SUBMIT, never at completion: a completion runs in IRQ or worker
// context where the running task has nothing to do with the one that issued
// the request, so charging there would bill an unrelated process.
//
// Reads are charged for every request that reaches the block layer, matching
// Linux's single `submit_bio` accounting point. Writes are charged where Linux
// charges them — the block-device write path — and NOT for buffered filesystem
// writes, whose pages are handed to writeback and submitted by a kernel thread
// that is not the writing task.

use crate::types::BlockOp;

/// Bill `bytes` of block-device read to the submitting task. # C: O(1)
pub fn account_read(bytes: u64) {
    if let Some(t) = sched::current() { sched::rusage_charge::io_read(t, bytes); }
}

/// Bill `bytes` of block-device write to the submitting task. # C: O(1)
pub fn account_write(bytes: u64) {
    if let Some(t) = sched::current() { sched::rusage_charge::io_write(t, bytes); }
}

/// Whether an op moves bytes IN from the device. Discard, flush and
/// write-zeroes carry no payload and are charged to neither direction — they
/// transfer nothing the submitter read or wrote. # C: O(1)
pub const fn charges_read(op: BlockOp) -> bool { matches!(op, BlockOp::Read) }

/// Byte count of a request whose length is expressed in device blocks.
/// # C: O(1)
pub const fn request_bytes(len_blocks: u32, block_size: u32) -> u64 {
    (len_blocks as u64) * (block_size as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reads_move_bytes_in_from_the_device() {
        assert!(charges_read(BlockOp::Read));
        assert!(!charges_read(BlockOp::Write));
        assert!(!charges_read(BlockOp::Flush));
        assert!(!charges_read(BlockOp::Discard));
        assert!(!charges_read(BlockOp::WriteZeroes { no_unmap: false }));
    }

    #[test]
    fn request_length_scales_by_the_devices_block_size_not_by_sectors() {
        assert_eq!(request_bytes(0, 512), 0);
        assert_eq!(request_bytes(8, 512), 4096);
        // A 4 KiB-block device: the same block count is 8x the bytes.
        assert_eq!(request_bytes(8, 4096), 32768);
    }
}
