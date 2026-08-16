use super::*;
use crate::chain::FatAccess;
use crate::geometry::Geometry;
use crate::uapi::{BAD_CLUSTER, EOF_CLUSTER};
use syscall::errno::Errno;

fn geo() -> Geometry {
    crate::geometry::resolve(&crate::boot::parse(&crate::tests_boot_sector()).unwrap())
}

fn table() -> FatTable { FatTable::new(alloc::vec![0u8; 512 * 8]) }

#[test]
fn an_entry_round_trips_through_the_table() {
    let mut t = table();
    t.set(7, 0x1234_5678).unwrap();
    assert_eq!(t.raw(7), Ok(0x1234_5678));
    // Little-endian, four bytes, at four times the cluster number.
    assert_eq!(&t.bytes()[28..32], &[0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn a_cluster_the_table_does_not_cover_is_an_error() {
    let t = table();
    assert!(t.covers(1023));
    assert!(!t.covers(1024));
    assert_eq!(t.raw(1024), Err(Errno::Eio));
}

#[test]
fn every_reserved_value_reads_as_the_end_of_the_chain() {
    let mut t = table();
    let g = geo();
    for value in [0xFFFF_FFF8u32, 0xFFFF_FFFE, EOF_CLUSTER] {
        t.set(5, value).unwrap();
        assert_eq!(Reader { table: &t, geo: &g }.get(5), Ok(EOF_CLUSTER), "value={value:#x}");
    }
}

#[test]
fn a_chain_running_into_a_free_cluster_is_an_inconsistent_volume() {
    let mut t = table();
    let g = geo();
    t.set(5, 0).unwrap();
    assert_eq!(Reader { table: &t, geo: &g }.get(5), Err(Errno::Eio));
}

#[test]
fn a_chain_running_into_a_bad_cluster_is_an_inconsistent_volume() {
    let mut t = table();
    let g = geo();
    t.set(5, BAD_CLUSTER).unwrap();
    assert_eq!(Reader { table: &t, geo: &g }.get(5), Err(Errno::Eio));
}

#[test]
fn a_link_outside_the_volume_is_refused() {
    let mut t = table();
    let g = geo();
    t.set(5, 9999).unwrap();
    assert_eq!(Reader { table: &t, geo: &g }.get(5), Err(Errno::Eio));
}

#[test]
fn a_reserved_cluster_is_never_read_as_part_of_a_chain() {
    let t = table();
    let g = geo();
    assert_eq!(Reader { table: &t, geo: &g }.get(0), Err(Errno::Eio));
    assert_eq!(Reader { table: &t, geo: &g }.get(1), Err(Errno::Eio));
}

#[test]
fn writing_a_contiguous_run_links_it_end_to_end() {
    let mut t = table();
    write_contiguous_chain(&mut t, 10, 4).unwrap();
    assert_eq!(t.raw(10), Ok(11));
    assert_eq!(t.raw(11), Ok(12));
    assert_eq!(t.raw(12), Ok(13));
    assert_eq!(t.raw(13), Ok(EOF_CLUSTER));
}

#[test]
fn a_run_of_one_becomes_a_chain_of_one() {
    let mut t = table();
    write_contiguous_chain(&mut t, 10, 1).unwrap();
    assert_eq!(t.raw(10), Ok(EOF_CLUSTER));
}

#[test]
fn a_run_of_none_writes_nothing() {
    let mut t = table();
    write_contiguous_chain(&mut t, 10, 0).unwrap();
    assert_eq!(t.raw(10), Ok(0));
}

#[test]
fn a_sector_of_the_table_is_located_for_writeback() {
    let t = table();
    let g = geo();
    assert_eq!(t.sector_index(&g, 0), 0);
    assert_eq!(t.sector_index(&g, 127), 0);
    assert_eq!(t.sector_index(&g, 128), 1);
    assert_eq!(t.sector_bytes(&g, 128).unwrap().len(), 512);
}
