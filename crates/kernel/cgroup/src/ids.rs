//! cgroup2 inode NUMBERS, drawn from the pseudo-inode registry
//! (`vfs::pseudo_ino`) so cgroupfs cannot mint into another owner's range.
//!
//! A number here is a `st_ino` value, never an identity test: a cgroup
//! directory is recognised by the `CgDirData` it carries in `i_private`
//! (`crate::cgid_from_dir_inode`), the way Linux recognises a kernfs node by
//! its ops vector. `0x6000_0000` used to be both `DIR_INO_BASE` and devpts'
//! `PTY_MASTER_INO_BASE`, so a cgroup directory with a small cgroup id decoded
//! as a PTY master under `devpts::pair_for_inode`.

use vfs::pseudo_ino::{CGROUP_DIR, CGROUP_FILE};
use vfs::Ino;

/// Bit width the control-file slot occupies in a control-file inode number;
/// the cgroup id sits above it.
pub(crate) const FILE_SLOT_BITS: u32 = 8;

/// `st_ino` of cgroup `cgid`'s directory. Folded into [`CGROUP_DIR`], so a
/// cgroup id past the region's width wraps inside it rather than minting into
/// the next owner's range. # C: O(1)
pub(crate) fn dir_ino(cgid: u64) -> Ino { CGROUP_DIR.at(cgid) }

/// `st_ino` of control-file `slot` inside cgroup `cgid` — `(cgid, slot)` so
/// one control file keeps one identity across lookups. Folded into
/// [`CGROUP_FILE`]. # C: O(1)
pub(crate) fn file_ino(cgid: u64, slot: u8) -> Ino {
    CGROUP_FILE.at((cgid << FILE_SLOT_BITS) | slot as u64)
}
