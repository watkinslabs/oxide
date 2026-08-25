use super::*;

#[test]
fn raw_write_is_cached_and_dirty_until_writeback() {
    let disk = medium(64);
    let m = mapping_over(disk.clone());
    assert_eq!(m.write_at(1000, &[0xAB; 300]).unwrap(), 300);
    assert_eq!(m.dirty_pages(), 1);
    assert_eq!(m.nrpages(), 1);
    assert!(on_medium(disk.as_ref(), 1000, 300).iter().all(|&b| b == 0));
    let mut buf = [0u8; 300];
    assert_eq!(m.read_at(1000, &mut buf).unwrap(), 300);
    assert!(buf.iter().all(|&b| b == 0xAB));
    m.fdatawrite();
    assert_eq!(m.fdatawait_keep_errors(), 0);
    assert_eq!(m.dirty_pages(), 0);
    assert!(on_medium(disk.as_ref(), 1000, 300).iter().all(|&b| b == 0xAB));
}

#[test]
fn shared_mapping_write_fault_dirties_the_same_device_cache_page() {
    let disk = medium(64);
    let m = mapping_over(disk.clone());
    m.write_at(0, &[0x2A; 64]).unwrap();
    m.fdatawrite();
    assert_eq!(m.fdatawait_keep_errors(), 0);
    assert_eq!(m.dirty_pages(), 0);
    assert_eq!(m.shared_frame(0).unwrap(), None);
    m.page_mkwrite(0).unwrap();
    assert_eq!(m.dirty_pages(), 1);
    m.fdatawrite();
    assert_eq!(m.fdatawait_keep_errors(), 0);
    assert_eq!(on_medium(disk.as_ref(), 0, 64), vec![0x2A; 64]);
}

#[test]
fn shared_mapping_write_fault_respects_write_seal_and_bounds() {
    let disk = medium(64);
    let m = mapping_over(disk);
    assert_eq!(m.page_mkwrite(8 * PG), Err(BlockError::Einval));
    m.seal_writes();
    assert_eq!(m.page_mkwrite(0), Err(BlockError::Erofs));
}

#[test]
fn write_seal_rejects_later_raw_writes_but_drains_existing_dirty_pages() {
    let disk = medium(64);
    let mapping = mapping_over(disk.clone());
    assert_eq!(mapping.write_at(0, &[0xA5; 512]), Ok(512));
    mapping.seal_writes();
    assert_eq!(mapping.write_at(512, &[0x5A; 512]), Err(BlockError::Erofs));
    assert_eq!(mapping.write_and_wait(), Ok(()));
    assert_eq!(on_medium(disk.as_ref(), 0, 512), vec![0xA5; 512]);
    mapping.unseal_writes();
    assert_eq!(mapping.write_at(512, &[0x5A; 512]), Ok(512));
}

#[test]
fn write_across_a_page_boundary_dirties_both_pages() {
    let disk = medium(64);
    let m = mapping_over(disk.clone());
    m.write_at(PG - 8, &[0x5A; 16]).unwrap();
    assert_eq!(m.dirty_pages(), 2);
    m.fdatawrite();
    m.fdatawait_keep_errors();
    assert_eq!(on_medium(disk.as_ref(), PG - 8, 16), vec![0x5A; 16]);
}

#[test]
fn io_past_end_of_device_is_short_not_an_error() {
    let disk = medium(2);
    let m = mapping_over(disk.clone());
    let mut buf = [0u8; 512];
    assert_eq!(m.read_at(1024, &mut buf).unwrap(), 0);
    assert_eq!(m.read_at(1000, &mut buf).unwrap(), 24);
    assert_eq!(m.write_at(1024, &[1u8; 8]).unwrap(), 0);
    assert_eq!(m.write_at(1020, &[1u8; 8]).unwrap(), 4);
}

#[test]
fn writeback_of_a_partial_last_page_writes_only_real_blocks() {
    let disk = medium(9);
    let m = mapping_over(disk.clone());
    m.write_at(PG, &[0x77; 512]).unwrap();
    m.fdatawrite();
    assert_eq!(m.fdatawait_keep_errors(), 0);
    assert_eq!(on_medium(disk.as_ref(), PG, 512), vec![0x77; 512]);
}
