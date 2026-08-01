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

/// Inverse of [`dir_ino`] — the cgroup id a DIRECTORY inode number encodes, or
/// `None` when the number is not in cgroupfs's directory region.
///
/// The answer is a CANDIDATE id, never an existence claim: the caller must ask
/// the hierarchy whether that cgroup is live. `at()` folds modulo the region
/// width, so an id past the region wraps onto a lower one — a file handle
/// therefore round-trips only for ids inside the region, and a wrapped id
/// resolves to whatever live cgroup shares its number, exactly as an inode
/// number collision would. # C: O(1)
pub(crate) fn cgid_of_dir_ino(ino: Ino) -> Option<u64> {
    if !CGROUP_DIR.contains(ino) { return None; }
    Some(ino - CGROUP_DIR.start())
}

/// Inverse of [`file_ino`] — the `(cgroup id, file slot)` a CONTROL-FILE inode
/// number encodes, or `None` outside cgroupfs's control-file region. A
/// candidate, like [`cgid_of_dir_ino`]. # C: O(1)
pub(crate) fn cgid_slot_of_file_ino(ino: Ino) -> Option<(u64, u8)> {
    if !CGROUP_FILE.contains(ino) { return None; }
    let packed = ino - CGROUP_FILE.start();
    Some((packed >> FILE_SLOT_BITS, (packed & 0xff) as u8))
}
