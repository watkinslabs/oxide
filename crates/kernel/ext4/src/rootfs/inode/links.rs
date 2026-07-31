// ext4 `i_links_count` ceilings. ext4 does NOT publish `s_max_links` to the
// VFS, so the generic `vfs_link`/`vfs_mkdir` ceiling never fires for it and
// every ext4 EMLINK is decided here — one owner for mkdir, link and rename.

use crate::superblock::RO_COMPAT_DIR_NLINK;

/// The `i_links_count` ceiling. The on-disk field is 16-bit, and the value is
/// kept below its true maximum so the count can never wrap.
pub const EXT4_LINK_MAX: u16 = 65000;

/// `EXT4_INODE_INDEX_FL` — the htree-indexed-directory flag. A directory
/// carrying it is the only kind allowed to stop tracking subdirectory links
/// accurately, which is what lifts the subdirectory ceiling.
const EXT4_INDEX_FL: u32 = 0x0000_1000;

/// `EXT4_DIR_LINK_MAX` — true when `dir` may gain no further subdirectory.
/// A filesystem advertising `dir_nlink` pins a large htree directory's link
/// count at 1 instead of counting, so such a directory has no ceiling at all;
/// everything else stops at [`EXT4_LINK_MAX`].
/// # C: O(1)
pub fn dir_link_max_reached(links_count: u16, i_flags: u32, feature_ro_compat: u32) -> bool {
    if links_count < EXT4_LINK_MAX { return false; }
    let unlimited = feature_ro_compat & RO_COMPAT_DIR_NLINK != 0 && i_flags & EXT4_INDEX_FL != 0;
    !unlimited
}

/// True when a directory's in-core link count leaves headroom no matter what
/// its on-disk flags say — the cheap precondition that keeps the common mkdir
/// off the inode table entirely. # C: O(1)
pub fn dir_link_headroom(nlink: u32) -> bool { nlink < EXT4_LINK_MAX as u32 }

/// The hardlink ceiling for a non-directory: a source already at
/// [`EXT4_LINK_MAX`] cannot gain another name. # C: O(1)
pub fn link_max_reached(src_links_count: u16) -> bool {
    src_links_count >= EXT4_LINK_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn under_ceiling_is_free() {
        assert!(!dir_link_max_reached(EXT4_LINK_MAX - 1, 0, 0));
        assert!(!dir_link_max_reached(EXT4_LINK_MAX - 1, EXT4_INDEX_FL, RO_COMPAT_DIR_NLINK));
    }
    #[test] fn at_ceiling_without_dir_nlink_blocks() {
        assert!(dir_link_max_reached(EXT4_LINK_MAX, 0, 0));
        assert!(dir_link_max_reached(EXT4_LINK_MAX, EXT4_INDEX_FL, 0),
            "the feature bit alone is what lifts the ceiling; the inode flag is not enough");
        assert!(dir_link_max_reached(EXT4_LINK_MAX, 0, RO_COMPAT_DIR_NLINK),
            "a non-htree directory still counts links, so it still has a ceiling");
    }
    #[test] fn htree_with_feature_is_unlimited() {
        assert!(!dir_link_max_reached(EXT4_LINK_MAX, EXT4_INDEX_FL, RO_COMPAT_DIR_NLINK));
        assert!(!dir_link_max_reached(u16::MAX, EXT4_INDEX_FL, RO_COMPAT_DIR_NLINK));
    }
    #[test] fn headroom_matches_the_ceiling() {
        assert!(dir_link_headroom(EXT4_LINK_MAX as u32 - 1));
        assert!(!dir_link_headroom(EXT4_LINK_MAX as u32));
        // Headroom must never claim room the full test would deny.
        for n in [0u32, 1, 65_000, 65_001] {
            if dir_link_headroom(n) { assert!(!dir_link_max_reached(n as u16, 0, 0)); }
        }
    }
    #[test] fn hardlink_ceiling() {
        assert!(!link_max_reached(EXT4_LINK_MAX - 1));
        assert!(link_max_reached(EXT4_LINK_MAX));
        assert!(link_max_reached(EXT4_LINK_MAX + 1));
    }
}
