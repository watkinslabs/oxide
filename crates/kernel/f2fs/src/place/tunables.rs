//! The placement thresholds one mount is running with.
//!
//! Live state rather than a re-read of the option set, because two of the four
//! are not option-derived at all: the armed policy is decided by the volume's
//! SIZE, and the recycling floor by the reserve the volume was formatted with.
//! Both are fixed at mount and read by every write after it, so they are stored
//! once here instead of being recomputed — a decision that recomputed its own
//! threshold per block would be a second place for the derivation to be wrong.

/// What this mount's write-placement decisions compare against.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Tunables {
    /// The in-place-update policies this mount has armed (`super::bits`).
    pub ipu_policy: u32,
    /// Occupancy above which the utilisation arms fire.
    pub min_ipu_util: u32,
    /// Dirty pages at or below which an `fsync` asks for in-place writes.
    pub min_fsync_blocks: u32,
    /// The floor of free sections a mount keeps above the reserve before it
    /// starts recycling segments.
    pub min_ssr_sections: u32,
}

/// A threshold a control may be RETUNED to, checked before it takes effect.
///
/// The three thresholds below carry no bound of their own: each is compared
/// against a count, and a value no count can reach turns the arm that reads it
/// off, which is a legitimate thing to ask for and is what the reference's own
/// controls accept. The one refusal is the WIDTH — the value is stored in a
/// word, and truncating a wider one would leave the mount running a threshold
/// nobody asked for while the attribute reported the value that was written.
/// # C: O(1)
pub fn store_threshold(value: u64) -> Result<u32, syscall::errno::Errno> {
    if value > u64::from(u32::MAX) { return Err(syscall::errno::Errno::Einval); }
    Ok(value as u32)
}

impl Tunables {
    /// What a mount of this volume starts with.
    ///
    /// `main_segments` decides the armed set and `reserved_sections` the
    /// recycling floor, so both come from the volume rather than from the line
    /// the caller mounted it with.
    /// # C: O(1)
    pub fn at_mount(lfs: bool, main_segments: u32, reserved_sections: u32) -> Self {
        Self {
            ipu_policy: super::ipu::mount_policy(lfs, main_segments),
            min_ipu_util: super::limits::DEF_MIN_IPU_UTIL,
            min_fsync_blocks: super::limits::DEF_MIN_FSYNC_BLOCKS,
            min_ssr_sections: reserved_sections,
        }
    }
}
