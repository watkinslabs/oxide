//! What an inode NUMBER is on a filesystem that has none.
//!
//! FAT stores no inode numbers. Every other filesystem's identity comes off
//! the medium; here it must be derived, and the derivation has to satisfy two
//! things at once: the same file must keep the same number across lookups, or
//! a cache above sees two files where there is one; and two different files
//! must not share a number, or a cache sees one where there are two.
//!
//! The reference derives it from the directory entry's position on disk, and
//! so does this. The rule is separated from the mount code because that code
//! reaches the block layer and cannot be tested; this can.

use crate::dirent::ShortEntry;

/// Where a directory's contents live.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DirLocation {
    /// The fixed root region of a FAT12/16 volume, which is not a chain.
    FixedRoot,
    /// A directory whose contents start at this cluster.
    Cluster(u32),
    /// A file: it names no directory contents, and is identified by the entry
    /// it came from and the directory that entry sits in.
    Entry { parent: u32, first_cluster: u32 },
}

/// Inode number of the root. Fixed, and deliberately not zero or one: a zero
/// inode reads as "no inode" to callers that test it, and one is conventional
/// for a filesystem's own root elsewhere in this tree.
pub const ROOT_INO: u64 = 1;

/// Marks a number as derived from a cluster rather than from the root, so a
/// file whose first cluster happens to be 1 cannot collide with the root.
const CLUSTER_TAG: u64 = 1 << 32;
/// Marks an EMPTY file's number, which cannot come from a cluster because it
/// has none.
const EMPTY_TAG: u64 = 1 << 33;

/// The inode number for an entry at `location`.
///
/// A file with contents is identified by its first cluster, which is unique
/// among live files: two files cannot share a cluster without the volume
/// being corrupt. An EMPTY file has no cluster at all, so it is identified by
/// where its entry sits — its parent directory — combined with a tag, which
/// is the best identity available and is stable for as long as the entry
/// stays put.
/// # C: O(1)
pub fn inode_number(location: &DirLocation, entry: Option<&ShortEntry>) -> u64 {
    match location {
        DirLocation::FixedRoot => ROOT_INO,
        DirLocation::Cluster(cluster) => CLUSTER_TAG | u64::from(*cluster),
        DirLocation::Entry { parent, first_cluster } => {
            let _ = entry;
            if *first_cluster == 0 { EMPTY_TAG | u64::from(*parent) }
            else { CLUSTER_TAG | u64::from(*first_cluster) }
        }
    }
}

/// Where `entry` sits, given the directory it was found in.
///
/// A directory becomes a location its own contents can be read from; a file
/// remembers the directory it came from, because that is what identifies it
/// when it holds no clusters.
/// # C: O(1)
pub fn location_of(entry: &ShortEntry, parent: &DirLocation) -> DirLocation {
    if entry.is_dir() {
        // A subdirectory's `..` entry names cluster 0 when the parent is the
        // fixed root, and the root of a FAT32 volume is an ordinary cluster.
        return DirLocation::Cluster(entry.cluster);
    }
    let parent_cluster = match parent {
        DirLocation::FixedRoot => 0,
        DirLocation::Cluster(c) => *c,
        DirLocation::Entry { first_cluster, .. } => *first_cluster,
    };
    DirLocation::Entry { parent: parent_cluster, first_cluster: entry.cluster }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dirent::{ATTR_ARCH, ATTR_DIR};

    fn entry(cluster: u32, attr: u8) -> ShortEntry {
        ShortEntry { raw_name: *b"NAME    EXT", attr, cluster, size: 0 }
    }

    /// The same file resolves to the same number every time, which is what
    /// keeps a cache above from seeing two files where there is one.
    #[test]
    fn the_same_entry_always_yields_the_same_number() {
        let parent = DirLocation::Cluster(2);
        let e = entry(9, ATTR_ARCH);
        let a = inode_number(&location_of(&e, &parent), Some(&e));
        let b = inode_number(&location_of(&e, &parent), Some(&e));
        assert_eq!(a, b);
    }

    /// Two different files do not share a number, which is what keeps a cache
    /// from seeing one file where there are two.
    #[test]
    fn two_files_do_not_share_a_number() {
        let parent = DirLocation::Cluster(2);
        let a = entry(9, ATTR_ARCH);
        let b = entry(10, ATTR_ARCH);
        assert_ne!(inode_number(&location_of(&a, &parent), Some(&a)),
                   inode_number(&location_of(&b, &parent), Some(&b)));
    }

    /// The root's number is fixed, and nothing derived from a cluster can
    /// collide with it — including a file whose first cluster is 1.
    #[test]
    fn nothing_collides_with_the_root() {
        assert_eq!(inode_number(&DirLocation::FixedRoot, None), ROOT_INO);
        let parent = DirLocation::Cluster(2);
        for cluster in [0u32, 1, 2, ROOT_INO as u32] {
            let e = entry(cluster, ATTR_ARCH);
            let ino = inode_number(&location_of(&e, &parent), Some(&e));
            assert_ne!(ino, ROOT_INO, "cluster {cluster}");
        }
        // ...and neither can a FAT32 root, whose cluster is an ordinary one.
        assert_ne!(inode_number(&DirLocation::Cluster(2), None), ROOT_INO);
    }

    /// An empty file holds no cluster, so its number cannot come from one.
    /// Deriving it from cluster zero would give every empty file on the
    /// volume the same number.
    #[test]
    fn empty_files_do_not_all_share_one_number() {
        let a = inode_number(&location_of(&entry(0, ATTR_ARCH), &DirLocation::Cluster(2)), None);
        let b = inode_number(&location_of(&entry(0, ATTR_ARCH), &DirLocation::Cluster(7)), None);
        assert_ne!(a, b, "two empty files in different directories");
        // Two empty files in the SAME directory do still share one, which is
        // the limit of what a position-free derivation can distinguish.
        let c = inode_number(&location_of(&entry(0, ATTR_ARCH), &DirLocation::Cluster(2)), None);
        assert_eq!(a, c);
    }

    /// An empty file's number cannot collide with a real file's, whatever
    /// cluster that file starts at.
    #[test]
    fn an_empty_file_cannot_collide_with_a_real_one() {
        let empty = inode_number(&location_of(&entry(0, ATTR_ARCH), &DirLocation::Cluster(5)), None);
        for cluster in [2u32, 5, 100, u32::MAX] {
            let real = inode_number(&location_of(&entry(cluster, ATTR_ARCH), &DirLocation::Cluster(5)), None);
            assert_ne!(empty, real, "cluster {cluster}");
        }
    }

    /// A directory becomes a location its contents can be read from; a file
    /// remembers where it came from instead.
    #[test]
    fn a_directory_becomes_readable_and_a_file_remembers_its_parent() {
        let parent = DirLocation::Cluster(2);
        assert_eq!(location_of(&entry(9, ATTR_DIR), &parent), DirLocation::Cluster(9));
        assert_eq!(location_of(&entry(9, ATTR_ARCH), &parent),
                   DirLocation::Entry { parent: 2, first_cluster: 9 });
        // From the fixed root, a file's parent is named zero — the root has no
        // cluster of its own.
        assert_eq!(location_of(&entry(9, ATTR_ARCH), &DirLocation::FixedRoot),
                   DirLocation::Entry { parent: 0, first_cluster: 9 });
    }
}
