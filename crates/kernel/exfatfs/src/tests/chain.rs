use super::*;
use crate::geometry::Geometry;
use crate::uapi::{ALLOC_FAT_CHAIN, ALLOC_NO_FAT_CHAIN, EOF_CLUSTER};
use syscall::errno::Errno;

/// A table given as entry values, indexed by cluster.
struct Table(alloc::vec::Vec<u32>);

impl FatAccess for Table {
    fn get(&self, cluster: u32) -> Result<u32, Errno> {
        self.0.get(cluster as usize).copied().ok_or(Errno::Eio)
    }
}

fn geo() -> Geometry {
    crate::geometry::resolve(&crate::boot::parse(&crate::tests_boot_sector()).unwrap())
}

/// 2 -> 5 -> 9 -> end, with everything else ending immediately.
fn linked() -> Table {
    let mut t = alloc::vec![EOF_CLUSTER; 64];
    t[2] = 5;
    t[5] = 9;
    t[9] = EOF_CLUSTER;
    Table(t)
}

#[test]
fn a_contiguous_run_answers_by_arithmetic_and_never_reads_the_table() {
    // A table that errors on every read: a contiguous walk must not touch it.
    struct Poison;
    impl FatAccess for Poison {
        fn get(&self, _: u32) -> Result<u32, Errno> { panic!("a contiguous run read the table") }
    }
    let chain = Chain::new(10, 4, ALLOC_NO_FAT_CHAIN);
    assert_eq!(cluster_at(&geo(), &Poison, &chain, 0), Ok(10));
    assert_eq!(cluster_at(&geo(), &Poison, &chain, 3), Ok(13));
    assert_eq!(walk(&geo(), &Poison, &chain), Ok(alloc::vec![10, 11, 12, 13]));
}

#[test]
fn a_chained_run_follows_the_table() {
    let chain = Chain::new(2, 3, ALLOC_FAT_CHAIN);
    assert_eq!(cluster_at(&geo(), &linked(), &chain, 0), Ok(2));
    assert_eq!(cluster_at(&geo(), &linked(), &chain, 1), Ok(5));
    assert_eq!(cluster_at(&geo(), &linked(), &chain, 2), Ok(9));
    assert_eq!(walk(&geo(), &linked(), &chain), Ok(alloc::vec![2, 5, 9]));
}

#[test]
fn an_index_past_the_declared_size_is_an_error_not_a_longer_file() {
    let chain = Chain::new(2, 3, ALLOC_FAT_CHAIN);
    assert_eq!(cluster_at(&geo(), &linked(), &chain, 3), Err(Errno::Eio));
}

#[test]
fn a_chain_shorter_than_its_declared_size_is_an_error() {
    let chain = Chain::new(2, 5, ALLOC_FAT_CHAIN);
    assert_eq!(walk(&geo(), &linked(), &chain), Err(Errno::Eio));
}

#[test]
fn an_empty_run_has_no_clusters() {
    let chain = Chain::empty();
    assert!(chain.is_empty());
    assert_eq!(walk(&geo(), &linked(), &chain), Ok(alloc::vec![]));
    assert_eq!(cluster_at(&geo(), &linked(), &chain, 0), Err(Errno::Eio));
}

#[test]
fn a_run_starting_at_cluster_zero_is_empty() {
    assert!(Chain::new(0, 3, ALLOC_FAT_CHAIN).is_empty());
}

#[test]
fn the_last_cluster_of_each_kind_of_run() {
    assert_eq!(last_cluster(&geo(), &linked(), &Chain::new(2, 3, ALLOC_FAT_CHAIN)), Ok(9));
    assert_eq!(last_cluster(&geo(), &linked(), &Chain::new(10, 4, ALLOC_NO_FAT_CHAIN)), Ok(13));
}

#[test]
fn counting_a_chain_follows_it_to_the_end() {
    assert_eq!(count(&geo(), &linked(), 2), Ok(3));
    assert_eq!(count(&geo(), &linked(), 0), Ok(0));
    assert_eq!(count(&geo(), &linked(), EOF_CLUSTER), Ok(0));
}

#[test]
fn a_loop_is_reported_rather_than_followed_forever() {
    let mut t = alloc::vec![EOF_CLUSTER; 64];
    t[2] = 3;
    t[3] = 2;
    assert_eq!(count(&geo(), &Table(t), 2), Err(Errno::Eio));
}

#[test]
fn a_link_outside_the_volume_is_an_error() {
    let mut t = alloc::vec![EOF_CLUSTER; 64];
    t[2] = 9999;
    assert_eq!(count(&geo(), &Table(t), 2), Err(Errno::Eio));
}

#[test]
fn the_flag_says_which_kind_of_run_it_is() {
    assert_eq!(flags_for(true), ALLOC_NO_FAT_CHAIN);
    assert_eq!(flags_for(false), ALLOC_FAT_CHAIN);
    assert!(Chain::new(2, 1, ALLOC_NO_FAT_CHAIN).contiguous());
    assert!(!Chain::new(2, 1, ALLOC_FAT_CHAIN).contiguous());
}
