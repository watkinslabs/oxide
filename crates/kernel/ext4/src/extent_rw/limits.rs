//! Bounded direct-I/O cluster limits for ext4 writeback.

/// Largest contiguous writeback cluster handed to the single-request virtio
/// bounce path. # C: O(1)
pub(crate) const DATA_WRITE_CLUSTER_BYTES: usize = 128 * 1024;
