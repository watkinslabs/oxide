//! Putting both copies down, in the order that survives a crash between them.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::checksum;
use crate::flags::FEATURE_SB_CHKSUM;
use crate::sbflags::{bits, SbFlags};
use crate::uapi::*;
use crate::volume::dnode::put32;

use super::raw::RawSuper;

/// Whether a commit may not proceed at all.
///
/// A repair of a bad copy is refused on a read-only MOUNT, but an ordinary
/// change is not: a mount can be read-only while the volume behind it is being
/// made writable, and that is exactly when the superblock has to be written.
/// A read-only MEDIUM refuses both — there is nowhere to put the bytes.
/// # C: O(1)
pub fn refuses(recover: bool, mount_ro: bool, hw_ro: bool) -> bool {
    (recover && mount_ro) || hw_ro
}

/// The copies a commit writes, in order.
///
/// The copy this mount does NOT believe goes first. A crash between the two
/// writes then leaves the believed copy as it was, and the volume mounts
/// unchanged; writing the believed copy first would leave a torn superblock in
/// the position every mount reads before it reads anything else. A repair
/// stops after the first: the believed copy is the one being copied FROM.
/// # C: O(1)
pub fn copies(valid: u64, recover: bool) -> Vec<u64> {
    let backup = valid ^ 1;
    if recover { vec![backup] } else { vec![backup, valid] }
}

/// Write the superblock back to the medium.
///
/// `recover` says this is the repair of a copy that failed its checks, which
/// writes only that copy and leaves the checksum alone — the bytes being
/// copied are already sealed, and resealing them would hide a difference
/// between what was read and what is being written.
/// # C: O(2 blocks)
pub fn commit_super<S: SectorSource>(source: &S, raw: &mut RawSuper, recover: bool,
                                     mount_ro: bool, flags: &mut SbFlags) -> Result<(), Errno> {
    if refuses(recover, mount_ro, !source.writable()) {
        // The write is owed, not abandoned: a later remount that can write
        // takes it, which is what makes a repair survive a read-only boot.
        flags.set(bits::NEED_SB_WRITE);
        return Err(Errno::Erofs);
    }
    if !recover { reseal(raw); }
    for copy in copies(raw.valid(), recover) { write_copy(source, raw, copy)?; }
    Ok(())
}

/// Recompute the copy's checksum over everything ahead of it, for a volume
/// that maintains one. # C: O(SUPER_SIZE)
pub fn reseal(raw: &mut RawSuper) {
    let Some(feature) = le32(raw.bytes(), SB_FEATURE) else { return };
    if feature & FEATURE_SB_CHKSUM == 0 { return; }
    let crc = checksum::crc32(&raw.bytes()[..SB_CRC]);
    put32(raw.bytes_mut(), SB_CRC, crc);
}

/// Put one copy down, leaving the rest of its block alone.
///
/// The first block carries a boot area ahead of the superblock that belongs to
/// nobody here, so the block is read, patched and written rather than built.
/// # C: O(BLKSIZE)
fn write_copy<S: SectorSource>(source: &S, raw: &RawSuper, copy: u64) -> Result<(), Errno> {
    let mut block = vec![0u8; BLKSIZE];
    source.read_sectors(copy, &mut block)?;
    block[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE].copy_from_slice(raw.bytes());
    source.write_sectors(copy, &block)
}

#[cfg(test)]
#[path = "../tests/sbwrite/commit.rs"]
mod tests;
