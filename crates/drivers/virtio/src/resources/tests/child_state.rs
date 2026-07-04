use super::*;

#[test]
fn child_resource_state_builds_required_resources() {
    let mut state =
        VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20)
            .with_device_cfg_va(0x30);
    state.set_queue(VALID_Q0);

    let resources = state
        .resources_for_child(VirtioChildRequirements::q0_device_cfg())
        .unwrap();

    assert_eq!(resources.cfg_va, 0x10);
    assert_eq!(resources.device_cfg_va, 0x30);
    assert_eq!(resources.require_queue(0), Some(VALID_Q0));
}

#[test]
fn child_resource_state_rejects_not_ready_transport() {
    let mut state = VirtioChildResourceState::new(0, 0x10, 0x20);
    state.set_queue(VALID_Q0);
    assert!(!state.ready_for_child(VirtioChildRequirements::q0()));

    let state = VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20);
    assert!(!state.ready_for_child(VirtioChildRequirements::q0()));

    let mut state = VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20);
    state.set_queue(VALID_Q0);
    assert!(!state.ready_for_child(VirtioChildRequirements::q0_device_cfg()));
    assert!(!state.ready_for_child(VirtioChildRequirements::net()));

    let state = state.with_net_boot_payloads(VirtioNetBootPayloads::new(0x1000, 64, 0x2000));
    assert!(!state.ready_for_child(VirtioChildRequirements::net()));
}

#[test]
fn child_probe_facts_expose_features_payloads_and_resources() {
    let mut state =
        VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20)
            .with_net_boot_payloads(VirtioNetBootPayloads::new(0x1000, 64, 0x2000));
    state.set_queue(VALID_Q0);
    let facts = VirtioChildProbeFacts::new(0x55, state);

    assert_eq!(facts.drv_features, 0x55);
    assert!(facts.net_boot_payloads().is_present());
    assert!(facts.resources_for_child(VirtioChildRequirements::q0()).is_some());
}

#[test]
fn transport_probe_result_builds_child_facts_and_frame_lists() {
    let mut queues = core::array::from_fn(|index| VirtQueueResource::new(index as u16, 0, 0, 0, 0, 0, 0));
    queues[0] = VALID_Q0;
    queues[1] = VirtQueueResource {
        index: 1,
        size: 8,
        desc_pa: 0x5000,
        driver_pa: 0x6000,
        device_pa: 0x7000,
        notify_va: 0x8000,
        notify_off: 4,
    };
    let result = VirtioTransportProbeResult::new(
        0x20,
        0x55,
        crate::VIRTIO_STATUS_DRIVER_OK,
        0x10,
        0x30,
        queues,
        VirtioNetBootPayloads::new(0x9000, 64, 0xa000),
    );

    let facts = result.child_facts();
    assert_eq!(facts.drv_features, 0x55);
    assert_eq!(facts.net_boot_payloads().rx_bufs[0].pa, 0x9000);
    assert_eq!(facts.net_boot_payloads().rx_bufs_len, 1);
    let resources = facts.resources_for_child(VirtioChildRequirements::net()).unwrap();
    assert_eq!(resources.cfg_va, 0x10);
    assert_eq!(resources.device_cfg_va, 0x30);
    assert_eq!(resources.require_queue(0), Some(queues[0]));
    assert_eq!(resources.require_queue(1), Some(queues[1]));

    assert_eq!(result.vring_frames(), alloc::vec![0x1000, 0x2000, 0x3000, 0x5000, 0x6000, 0x7000]);
    assert_eq!(result.net_payload_frames(), alloc::vec![0x9000, 0xa000]);
}

#[test]
fn owned_probe_frames_drain_all_failed_probe_resources_once() {
    let mut queues = core::array::from_fn(|index| VirtQueueResource::new(index as u16, 0, 0, 0, 0, 0, 0));
    queues[0] = VirtQueueResource {
        index: 0,
        size: 8,
        desc_pa: 0x1000,
        driver_pa: 0x2000,
        device_pa: 0x3000,
        notify_va: 0x4000,
        notify_off: 2,
    };
    queues[1] = VirtQueueResource {
        index: 1,
        size: 8,
        desc_pa: 0x1000,
        driver_pa: 0x5000,
        device_pa: 0x6000,
        notify_va: 0x7000,
        notify_off: 4,
    };
    let result = VirtioTransportProbeResult::new(
        0x20,
        0x55,
        crate::VIRTIO_STATUS_DRIVER_OK,
        0x10,
        0x30,
        queues,
        VirtioNetBootPayloads::new(0x6000, 64, 0x8000),
    );
    let mut owned = VirtioProbeOwnedFrames::from_probe_result(&result);

    assert_eq!(owned.take_all(), alloc::vec![0x1000, 0x2000, 0x3000, 0x5000, 0x6000, 0x8000]);
    assert!(owned.is_empty());
    assert!(owned.take_all().is_empty());
}

#[test]
fn owned_probe_frames_publish_only_transfers_vring_frames() {
    let mut queues = core::array::from_fn(|index| VirtQueueResource::new(index as u16, 0, 0, 0, 0, 0, 0));
    queues[0] = VALID_Q0;
    let result = VirtioTransportProbeResult::new(
        0x20,
        0x55,
        crate::VIRTIO_STATUS_DRIVER_OK,
        0x10,
        0x30,
        queues,
        VirtioNetBootPayloads::new(0x9000, 64, 0xa000),
    );
    let mut owned = VirtioProbeOwnedFrames::from_probe_result(&result);

    assert_eq!(owned.take_vring_frames(), alloc::vec![0x1000, 0x2000, 0x3000]);
    assert_eq!(owned.payload_frames(), &[0x9000, 0xa000]);
    assert_eq!(owned.take_all(), alloc::vec![0x9000, 0xa000]);
    assert!(owned.is_empty());
}
