use super::*;

#[test]
fn sync_bdevs_submit_half_writes_dirty_device_pages_back() {
    let raw = medium(8);
    let idx = crate::registry::register("vdx", raw.clone());
    let devt = crate::registry::dev_t_of("vdx", idx).unwrap();
    assert!(crate::registry::open_by_dev(devt));
    let disk = crate::registry::by_dev(devt).unwrap();
    disk.mapping.write_at(0, &[0xE1; 128]).unwrap();
    assert!(on_medium(raw.as_ref(), 0, 128).iter().all(|&b| b == 0));
    sync_bdevs(false);
    assert_eq!(on_medium(raw.as_ref(), 0, 128), vec![0xE1; 128]);
    sync_bdevs(true);
    assert_eq!(disk.mapping.writeback_pages(), 0);
    crate::registry::close_by_dev(devt);
    crate::registry::unregister("vdx");
}

#[test]
fn sync_bdevs_skips_a_disk_with_no_pages_or_no_opener() {
    let raw = medium(8);
    let idx = crate::registry::register("vdy", raw.clone());
    let devt = crate::registry::dev_t_of("vdy", idx).unwrap();
    let disk = crate::registry::by_dev(devt).unwrap();
    assert_eq!(disk.mapping.nrpages(), 0);
    sync_bdevs(false);
    sync_bdevs(true);
    disk.mapping.write_at(0, &[0xE2; 16]).unwrap();
    assert_eq!(disk.opener_count(), 0);
    sync_bdevs(false);
    assert_eq!(disk.mapping.dirty_pages(), 1);
    assert!(crate::registry::open_by_dev(devt));
    sync_bdevs(false);
    assert_eq!(disk.mapping.dirty_pages(), 0);
    crate::registry::close_by_dev(devt);
    crate::registry::unregister("vdy");
}

#[test]
fn disk_removal_writes_the_cache_back_and_drops_it() {
    let raw = medium(8);
    let idx = crate::registry::register("vdz", raw.clone());
    let devt = crate::registry::dev_t_of("vdz", idx).unwrap();
    let disk = crate::registry::by_dev(devt).unwrap();
    disk.mapping.write_at(0, &[0xF0; 32]).unwrap();
    assert!(crate::registry::unregister("vdz"));
    assert_eq!(on_medium(raw.as_ref(), 0, 32), vec![0xF0; 32]);
    assert_eq!(disk.mapping.nrpages(), 0);
}
