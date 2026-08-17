//! The volume and file facts the admission ladder reads, gathered from a
//! mounted volume.
//!
//! Kept apart from the ladder so the ladder stays a pure function of stated
//! facts: every ordering in it is then exercised by naming the facts, with no
//! volume to arrange and no medium to write. Gathering is the only part that
//! needs a real volume, and it does no deciding.

use sectors::SectorSource;

use crate::node::Inode;
use crate::volume::Volume;

use super::perm::{FileFacts, VolFacts};

/// The volume as the ladder reads it. # C: O(1)
pub fn vol_facts<S: SectorSource>(v: &Volume<S>) -> VolFacts {
    let sb = v.super_block();
    let cp = v.checkpoint();
    let main = u64::from(sb.main_blkaddr);
    VolFacts {
        features: sb.feature,
        writable: v.writable(),
        cp_error: cp.flags & crate::flags::CP_ERROR_FLAG != 0,
        cp_disabled: cp.flags & crate::flags::CP_DISABLED_FLAG != 0,
        // A volume that cannot checkpoint still answers, so long as it is not
        // ALSO out of room: the pair is what Linux tests, and testing only
        // the switch would refuse every command on a deliberately
        // checkpoint-disabled mount.
        checkpoint_ready: cp.flags & crate::flags::CP_DISABLED_FLAG == 0
            || v.space().free > 0,
        supports_discard: v.discards(),
        // One entry per member, and a volume that names none still has one,
        // so this is never zero.
        device_count: u32::try_from(v.devices().len()).unwrap_or(u32::MAX),
        large_section: sb.segs_per_sec > 1,
        compress_mode_user: v.options().compress.mode == crate::opts::CompressMode::User,
        compress_backend_ready: true,
        main_blkaddr: main,
        max_blkaddr: main
            + u64::from(sb.segment_count_main) * u64::from(crate::uapi::BLKS_PER_SEG),
        max_file_blocks: crate::node::path::max_block(
            crate::uapi::DEF_ADDRS_PER_INODE),
    }
}

/// One inode as the ladder reads it. # C: O(1)
pub fn file_facts(i: &Inode) -> FileFacts {
    use crate::flags::*;
    FileFacts {
        is_reg: crate::mode::file_type(i.mode) == vfs_regular(),
        is_dir: crate::mode::file_type(i.mode) == vfs_directory(),
        size: i.size,
        // The inode's own node block is counted, so a file with data holds
        // more than one.
        has_blocks: i.blocks > 1,
        // Being mid-atomic-write is mount state, not medium state, and this
        // build keeps none, so no inode reads as atomic.
        atomic: false,
        compressed: i.compressed(),
        compress_released: i.has(COMPRESS_RELEASED),
        compr_blocks: i.compr_blocks,
        pinned: i.has(PIN_FILE),
        verity: i.verity(),
        encrypted: i.encrypted(),
        immutable: i.flags & F2FS_IMMUTABLE_FL != 0,
        append_only: i.flags & F2FS_APPEND_FL != 0,
        // The flag alone, as the reference reads it. Whether the extent it
        // carries matches a real member is settled when the inode is read;
        // one that does not is never handed out.
        device_alias: crate::devices::alias::is_alias(i.flags),
        no_extent: false,
        inline_data: i.inline_data(),
    }
}

fn vfs_regular() -> vfs::FileType { vfs::FileType::Regular }
fn vfs_directory() -> vfs::FileType { vfs::FileType::Directory }
