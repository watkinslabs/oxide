//! Which newly claimed clusters must be cleared before use.

use super::geo;
use crate::cluster_alloc::{zero_range, NewCluster};
use crate::geometry::FatWidth;

/// A directory cluster is zeroed and a file's is not. A directory is read to
/// its first zero name byte, so stale bytes there read back as file names; a
/// file is read only as far as its recorded size, so stale bytes are
/// unreachable and zeroing them would double the cost of growing every file.
#[test]
fn only_a_directory_cluster_must_be_zeroed() {
    assert!(NewCluster::Directory.must_zero());
    assert!(!NewCluster::File.must_zero());
}

/// The range to clear is exactly the cluster: its first sector and the
/// volume's sectors per cluster.
#[test]
fn the_range_is_the_whole_cluster_and_nothing_else() {
    let (g, _) = geo(FatWidth::Fat32);
    let first = g.cluster_sector(2).expect("cluster 2 exists");
    assert_eq!(zero_range(&g, 2, NewCluster::Directory), Some((first, g.sec_per_clus)));
    assert_eq!(zero_range(&g, 2, NewCluster::File), None);
}

/// A cluster this volume does not have names no sectors to clear.
#[test]
fn a_cluster_off_the_volume_has_no_range() {
    let (g, _) = geo(FatWidth::Fat16);
    assert_eq!(zero_range(&g, g.max_cluster, NewCluster::Directory), None);
    assert_eq!(zero_range(&g, 1, NewCluster::Directory), None, "a reserved entry names no data");
}
