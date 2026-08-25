use super::*;

fn coherent_stack(blocks: u64) -> (Arc<MemDisk<InodeClass>>, Arc<BdevMapping>, Arc<dyn BlockDevice>) {
    let disk = medium(blocks);
    let m = mapping_over(disk.clone());
    let published = CoherentDev::wrap(disk.clone(), Arc::downgrade(&m));
    (disk, m, published)
}
fn fs_write(dev: &dyn BlockDevice, block: u64, byte: u8) {
    let mut req = BlockRequest::new_write(block, 1, vec![byte; BS as usize]);
    dev.submit_sync(&mut req).unwrap();
}

#[test]
fn filesystem_write_is_visible_to_a_raw_read_of_the_same_block() {
    let (disk, m, published) = coherent_stack(64);
    let mut buf = [0u8; 8];
    m.read_at(0, &mut buf).unwrap();
    assert!(m.is_resident(0));
    fs_write(published.as_ref(), 0, 0x33);
    m.read_at(0, &mut buf).unwrap();
    m.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, [0x33; 8]);
    fs_write(disk.as_ref(), 0, 0x44);
    m.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, [0x33; 8]);
}

#[test]
fn raw_write_is_visible_to_a_filesystem_read_of_the_same_block() {
    let (_disk, m, published) = coherent_stack(64);
    m.write_at(0, &[0x55; 16]).unwrap();
    assert_eq!(m.dirty_pages(), 1);
    let mut req = BlockRequest::new_read(0, 1, BS);
    published.submit_sync(&mut req).unwrap();
    assert_eq!(&req.buffer[..16], &[0x55; 16]);
}

#[test]
fn filesystem_write_over_a_dirty_page_orders_the_cached_write_first() {
    let (disk, m, published) = coherent_stack(64);
    m.write_at(0, &[0x66; 16]).unwrap();
    m.write_at(BS as u64, &[0x99; 16]).unwrap();
    fs_write(published.as_ref(), 0, 0x77);
    assert_eq!(on_medium(disk.as_ref(), 0, 4), vec![0x77; 4]);
    assert_eq!(on_medium(disk.as_ref(), BS as u64, 16), vec![0x99; 16]);
}

#[test]
fn a_disk_with_no_cached_pages_is_not_reconciled() {
    let (_disk, m, published) = coherent_stack(64);
    assert_eq!(m.nrpages(), 0);
    fs_write(published.as_ref(), 0, 0x88);
    assert_eq!(m.nrpages(), 0);
}

#[test]
fn invalidate_drops_clean_pages_and_keeps_dirty_ones() {
    let disk = medium(64);
    let m = mapping_over(disk.clone());
    let mut buf = [0u8; 8];
    m.read_at(0, &mut buf).unwrap();
    m.write_at(PG, &[0x2A; 8]).unwrap();
    assert_eq!(m.nrpages(), 2);
    assert_eq!(m.invalidate_clean(), 1);
    assert!(!m.is_resident(0));
    assert!(m.is_resident(PG));
    assert_eq!(m.nrpages(), 1);
}
