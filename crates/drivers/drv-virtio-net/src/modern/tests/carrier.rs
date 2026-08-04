use super::*;

#[test]
fn carrier_is_not_read_from_a_device_that_never_offered_the_status_feature() {
    static MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 9];
    let resources = resources_with_mac(&MAC);
    assert!(super::super::state::read_device_carrier(resources, virtio::VIRTIO_NET_F_MAC));
    assert!(super::super::state::read_device_carrier(resources, 0));
    let bare = virtio::VirtioResources::new(1, 1);
    assert!(super::super::state::read_device_carrier(bare, virtio::VIRTIO_NET_F_STATUS));
}

#[test]
fn carrier_follows_the_link_up_bit_of_a_published_status_word() {
    static UP: [u8; 8] = [0x02, 0, 0, 0, 0, 9, 0x01, 0x00];
    static DOWN: [u8; 8] = [0x02, 0, 0, 0, 0, 9, 0x00, 0x00];
    let up = virtio::VirtioResources::new(1, 1).with_device_cfg_va(UP.as_ptr() as u64);
    let down = virtio::VirtioResources::new(1, 1).with_device_cfg_va(DOWN.as_ptr() as u64);
    assert!(super::super::state::read_device_carrier(up, virtio::VIRTIO_NET_F_STATUS));
    assert!(!super::super::state::read_device_carrier(down, virtio::VIRTIO_NET_F_STATUS));
}

#[test]
fn a_config_refresh_rechecks_every_registered_device_status() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    static UP: [u8; 8] = [0x02, 0, 0, 0, 0, 1, 0x01, 0x00];
    static DOWN: [u8; 8] = [0x02, 0, 0, 0, 0, 2, 0x00, 0x00];
    let mut up = state(1);
    up.device_cfg_va = UP.as_ptr() as u64;
    up.drv_features = virtio::VIRTIO_NET_F_STATUS;
    let mut down = state(2);
    down.device_cfg_va = DOWN.as_ptr() as u64;
    down.drv_features = virtio::VIRTIO_NET_F_STATUS;
    MODERN_DEVS.lock().extend([up, down]);

    assert_eq!(super::super::state::carrier_updates(), alloc::vec![(key(1), true), (key(2), false)]);
}

#[test]
fn the_shared_queue_zero_vector_runs_the_config_refresh_handler() {
    let profile = transport_profile();
    let handler = profile.msix0_handler.expect("net profile must bind config vector");
    assert_eq!(handler as *const (), config_changed as *const ());
}
