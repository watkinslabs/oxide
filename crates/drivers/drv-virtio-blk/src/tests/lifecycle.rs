use super::*;

const COMMON_CFG_BYTES: usize = 0x20;
const WAIT_OBSERVE_SPINS: usize = 20_000;
const CFG_STATUS_IDX: usize = virtio::common_cfg::CFG_DEVICE_STATUS as usize;
const LIVE_STATUS: u8 = virtio::VIRTIO_STATUS_ACKNOWLEDGE
    | virtio::VIRTIO_STATUS_DRIVER
    | virtio::VIRTIO_STATUS_FEATURES_OK
    | virtio::VIRTIO_STATUS_DRIVER_OK;

fn wait_until_frozen(state: &crate::modern::BlkState) {
    for _ in 0..WAIT_OBSERVE_SPINS {
        if state.frozen_for_tests() {
            return;
        }
        std::thread::yield_now();
    }
    panic!("virtio-blk teardown did not freeze new I/O");
}

fn cfg_with_live_status() -> [u8; COMMON_CFG_BYTES] {
    let mut cfg = [0u8; COMMON_CFG_BYTES];
    cfg[CFG_STATUS_IDX] = LIVE_STATUS;
    cfg
}

#[test]
fn remove_blk_unregisters_block_disk_and_device_node() {
    let seq = TEST_DISK_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!("vdtest{}", seq);
    let bus = 0xf0;
    let device = (seq as u8).wrapping_add(1);
    let function = 0;
    let device_key = child_key(bus, device, function);

    assert_ne!(crate::modern::test_publish_record(bus, device, function, &name), 0);
    assert!(crate::modern::test_has_record(bus, device, function));
    assert!(block::registry::by_name(&name).is_some());
    assert!(drv::devices().iter().any(|d| d.bus == "block" && d.addr == name));
    let stale_disk = block::registry::by_name(&name).unwrap();
    let stale_dev_t = block::registry::dev_t_of(&name, stale_disk.index);

    let duplicate = format!("vdtest{}dup", seq);
    assert_eq!(crate::modern::test_publish_record(bus, device, function, &duplicate), 0);
    assert!(block::registry::by_name(&duplicate).is_none());
    assert!(!drv::devices().iter().any(|d| d.bus == "block" && d.addr == duplicate));

    assert!(crate::modern::remove_blk(device_key));
    assert!(!crate::modern::test_has_record(bus, device, function));
    assert!(block::registry::by_name(&name).is_none());
    assert!(block::registry::by_dev(stale_dev_t.unwrap()).is_none());
    assert!(!drv::devices().iter().any(|d| d.bus == "block" && d.addr == name));
    let mut req = BlockRequest::new_read(0, 1, 512);
    assert_eq!(stale_disk.dev.submit_sync(&mut req), Err(BlockError::Eio));

    assert!(!crate::modern::remove_blk(device_key));

    let rebound = format!("vdtest{}r", seq);
    assert_ne!(crate::modern::test_publish_record(bus, device, function, &rebound), 0);
    let rebound_disk = block::registry::by_name(&rebound).unwrap();
    let rebound_dev_t = block::registry::dev_t_of(&rebound, rebound_disk.index);
    assert!(crate::modern::remove_blk(device_key));
    assert!(block::registry::by_name(&rebound).is_none());
    assert!(block::registry::by_dev(rebound_dev_t.unwrap()).is_none());
}

#[test]
fn remove_blk_selects_only_matching_device_record() {
    const TEST_BUS: u8 = 0xd0;
    const TEST_FUNCTION: u8 = 0;

    let seq = TEST_DISK_SEQ.fetch_add(1, Ordering::Relaxed);
    let first_name = format!("vdtest{}a", seq);
    let second_name = format!("vdtest{}b", seq);
    let first_device = (seq as u8).wrapping_add(1);
    let second_device = first_device.wrapping_add(1);
    let first_key = child_key(TEST_BUS, first_device, TEST_FUNCTION);
    let second_key = child_key(TEST_BUS, second_device, TEST_FUNCTION);

    assert_ne!(crate::modern::test_publish_record(TEST_BUS, first_device, TEST_FUNCTION, &first_name), 0);
    assert_ne!(crate::modern::test_publish_record(TEST_BUS, second_device, TEST_FUNCTION, &second_name), 0);
    assert!(crate::modern::test_has_record(TEST_BUS, first_device, TEST_FUNCTION));
    assert!(crate::modern::test_has_record(TEST_BUS, second_device, TEST_FUNCTION));
    assert!(block::registry::by_name(&first_name).is_some());
    let second_disk = block::registry::by_name(&second_name).unwrap();
    let second_dev_t = block::registry::dev_t_of(&second_name, second_disk.index);

    assert!(crate::modern::remove_blk(first_key));
    assert!(!crate::modern::test_has_record(TEST_BUS, first_device, TEST_FUNCTION));
    assert!(crate::modern::test_has_record(TEST_BUS, second_device, TEST_FUNCTION));
    assert!(block::registry::by_name(&first_name).is_none());
    assert!(block::registry::by_name(&second_name).is_some());
    assert!(block::registry::by_dev(second_dev_t.unwrap()).is_some());

    assert!(!crate::modern::remove_blk(first_key));
    assert!(crate::modern::remove_blk(second_key));
    assert!(!crate::modern::test_has_record(TEST_BUS, second_device, TEST_FUNCTION));
    assert!(block::registry::by_name(&second_name).is_none());
    assert!(block::registry::by_dev(second_dev_t.unwrap()).is_none());
}

#[test]
fn remove_waits_for_inflight_owner_before_reset_and_blocks_new_io() {
    let mut cfg = cfg_with_live_status();
    let state = std::sync::Arc::new(crate::modern::BlkState::for_test_cfg(cfg.as_mut_ptr() as u64));
    state.hold_inflight_for_tests();

    let owner = state.clone();
    let teardown = std::thread::spawn(move || owner.remove_for_tests());
    wait_until_frozen(&state);

    assert_eq!(cfg[CFG_STATUS_IDX], LIVE_STATUS);
    let mut req = BlockRequest::new_read(0, 1, blk::VIRTIO_BLK_SECTOR_BYTES);
    assert_eq!(state.submit_sync(&mut req), Err(BlockError::Eio));

    state.release_inflight_for_tests();
    teardown.join().expect("remove thread must finish");
    assert_eq!(cfg[CFG_STATUS_IDX], 0);
}

#[test]
fn shutdown_blk_quiesces_without_unregistering_publication() {
    let seq = TEST_DISK_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = format!("vdtest{}shutdown", seq);
    let bus = 0xe0;
    let device = (seq as u8).wrapping_add(1);
    let function = 0;
    let device_key = child_key(bus, device, function);

    assert_ne!(crate::modern::test_publish_record(bus, device, function, &name), 0);
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

#[test]
fn shutdown_waits_for_inflight_owner_before_reset_and_blocks_new_io() {
    let mut cfg = cfg_with_live_status();
    let state = std::sync::Arc::new(crate::modern::BlkState::for_test_cfg(cfg.as_mut_ptr() as u64));
    state.hold_inflight_for_tests();

    let owner = state.clone();
    let teardown = std::thread::spawn(move || owner.shutdown_for_tests());
    wait_until_frozen(&state);

    assert_eq!(cfg[CFG_STATUS_IDX], LIVE_STATUS);
    let mut req = BlockRequest::new_write(0, 1, vec![0u8; blk::VIRTIO_BLK_SECTOR_BYTES as usize]);
    assert_eq!(state.submit_sync(&mut req), Err(BlockError::Eio));

    state.release_inflight_for_tests();
    teardown.join().expect("shutdown thread must finish");
    assert_eq!(cfg[CFG_STATUS_IDX], 0);
}
