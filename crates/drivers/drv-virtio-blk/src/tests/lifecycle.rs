use super::*;

#[test]
fn remove_blk_unregisters_block_disk_and_device_node() {
    let seq = TEST_DISK_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!("vdtest{}", seq);
    let bus = 0xf0;
    let device = (seq as u8).wrapping_add(1);
    let function = 0;
    let device_key = child_key(bus, device, function);

    assert_eq!(crate::modern::test_publish_record(bus, device, function, &name), 1);
    assert!(crate::modern::test_has_record(bus, device, function));
    assert!(block::registry::by_name(&name).is_some());
    assert!(drv::devices().iter().any(|d| d.bus == "block" && d.addr == name));
    let stale_disk = block::registry::by_name(&name).unwrap();

    let duplicate = format!("vdtest{}dup", seq);
    assert_eq!(crate::modern::test_publish_record(bus, device, function, &duplicate), 0);
    assert!(block::registry::by_name(&duplicate).is_none());
    assert!(!drv::devices().iter().any(|d| d.bus == "block" && d.addr == duplicate));

    assert!(crate::modern::remove_blk(device_key));
    assert!(!crate::modern::test_has_record(bus, device, function));
    assert!(block::registry::by_name(&name).is_none());
    assert!(!drv::devices().iter().any(|d| d.bus == "block" && d.addr == name));
    let mut req = BlockRequest::new_read(0, 1, 512);
    assert_eq!(stale_disk.dev.submit_sync(&mut req), Err(BlockError::Eio));

    assert!(!crate::modern::remove_blk(device_key));

    let rebound = format!("vdtest{}r", seq);
    assert_ne!(crate::modern::test_publish_record(bus, device, function, &rebound), 0);
    assert!(block::registry::by_name(&rebound).is_some());
    assert!(crate::modern::remove_blk(device_key));
    assert!(block::registry::by_name(&rebound).is_none());
}

#[test]
fn shutdown_blk_quiesces_without_unregistering_publication() {
    let seq = TEST_DISK_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!("vdtest{}shutdown", seq);
    let bus = 0xe0;
    let device = (seq as u8).wrapping_add(1);
    let function = 0;
    let device_key = child_key(bus, device, function);

    assert_eq!(crate::modern::test_publish_record(bus, device, function, &name), 1);
    assert!(crate::modern::test_has_record(bus, device, function));
    let disk = block::registry::by_name(&name).unwrap();

    assert!(crate::modern::shutdown_blk(device_key));
    assert!(crate::modern::test_has_record(bus, device, function));
    assert!(block::registry::by_name(&name).is_some());
    assert!(drv::devices().iter().any(|d| d.bus == "block" && d.addr == name));

    let mut req = BlockRequest::new_read(0, 1, 512);
    assert_eq!(disk.dev.submit_sync(&mut req), Err(BlockError::Eio));

    assert!(crate::modern::remove_blk(device_key));
    assert!(block::registry::by_name(&name).is_none());
}
