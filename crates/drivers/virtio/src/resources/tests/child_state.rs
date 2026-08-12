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
    let resources = facts.resources_for_child(VirtioChildRequirements::q0()).unwrap();
    assert_eq!(resources.drv_features, 0x55);
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
    assert_eq!(result.net_payload_frames(), alloc::vec![
        VirtioDmaFrame { pa: 0x9000, dma: 0x9000 },
        VirtioDmaFrame { pa: 0xa000, dma: 0xa000 },
    ]);
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
    let mut owned = VirtioProbeOwnedFrames::from_probe_result(&result, None);

    let all = owned.take_all();
    assert_eq!(all.vring_frames, alloc::vec![
        VirtioDmaFrame { pa: 0x1000, dma: 0x1000 },
        VirtioDmaFrame { pa: 0x2000, dma: 0x2000 },
        VirtioDmaFrame { pa: 0x3000, dma: 0x3000 },
        VirtioDmaFrame { pa: 0x5000, dma: 0x5000 },
        VirtioDmaFrame { pa: 0x6000, dma: 0x6000 },
    ]);
    assert_eq!(all.payload_frames, alloc::vec![VirtioDmaFrame { pa: 0x8000, dma: 0x8000 }]);
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
    let mut owned = VirtioProbeOwnedFrames::from_probe_result(&result, None);

    assert_eq!(owned.take_vring_frames(), alloc::vec![
        VirtioDmaFrame { pa: 0x1000, dma: 0x1000 },
        VirtioDmaFrame { pa: 0x2000, dma: 0x2000 },
        VirtioDmaFrame { pa: 0x3000, dma: 0x3000 },
    ]);
    assert_eq!(owned.payload_frames(), &[
        VirtioDmaFrame { pa: 0x9000, dma: 0x9000 },
        VirtioDmaFrame { pa: 0xa000, dma: 0xa000 },
    ]);
    assert_eq!(owned.take_all().payload_frames, alloc::vec![
        VirtioDmaFrame { pa: 0x9000, dma: 0x9000 },
        VirtioDmaFrame { pa: 0xa000, dma: 0xa000 },
    ]);
    assert!(owned.is_empty());
}

const VALID_POLL_Q1: VirtQueueResource = VirtQueueResource {
    index: POLL_QUEUE_INDEX,
    size: 8,
    desc_pa: 0x5000,
    driver_pa: 0x6000,
    device_pa: 0x7000,
    notify_va: 0x8000,
    notify_off: 3,
};

/// A device that programmed the optional poll queue hands it to the child; a
/// device that did not still probes, without it. Both halves matter: the
/// first is what makes an interrupt-free queue reachable at all, and the
/// second is what keeps a single-queue device (QEMU's `num-queues=1` default)
/// bootable instead of failing its probe.
#[test]
fn an_optional_queue_is_handed_over_when_present_and_withheld_when_absent() {
    let requirements =
        VirtioChildRequirements::q0_device_cfg().with_optional_queue(POLL_QUEUE_INDEX as usize);

    let mut with_poll =
        VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20)
            .with_device_cfg_va(0x30);
    with_poll.set_queue(VALID_Q0);
    with_poll.set_queue(VALID_POLL_Q1);
    let resources = with_poll.resources_for_child(requirements).unwrap();
    assert_eq!(resources.require_queue(POLL_QUEUE_INDEX), Some(VALID_POLL_Q1));

    let mut without_poll =
        VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20)
            .with_device_cfg_va(0x30);
    without_poll.set_queue(VALID_Q0);
    let resources = without_poll
        .resources_for_child(requirements)
        .expect("a missing OPTIONAL queue must not fail the probe");
    assert_eq!(resources.require_queue(POLL_QUEUE_INDEX), None);
}

/// An optional queue the transport left unprogrammed is reported as absent
/// rather than handed over as a zero-sized ring a driver would then use.
#[test]
fn an_optional_queue_that_was_never_programmed_is_not_handed_over() {
    let requirements =
        VirtioChildRequirements::q0_device_cfg().with_optional_queue(POLL_QUEUE_INDEX as usize);
    let mut state = VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20)
        .with_device_cfg_va(0x30);
    state.set_queue(VALID_Q0);
    state.set_queue(VirtQueueResource::new(POLL_QUEUE_INDEX, 0, 0, 0, 0, 0, 0));

    let resources = state.resources_for_child(requirements).unwrap();

    assert_eq!(resources.require_queue(POLL_QUEUE_INDEX), None);
}

/// The whole point of the poll queue: the transport must have NO interrupt
/// handler to bind for it, which is what leaves its `queue_msix_vector` at the
/// no-vector sentinel and the device with nothing to raise.
#[test]
fn the_block_poll_profile_registers_no_interrupt_handler_for_its_poll_queue() {
    fn handler() {}
    let profile = VirtioTransportProfile::q0_device_cfg_poll_q1(0, Some(handler as fn()));

    let plan = profile.queue_plans[POLL_QUEUE_INDEX as usize].expect("poll queue is planned");
    assert_eq!(plan.index, POLL_QUEUE_INDEX);
    assert!(plan.msix_handler.is_none(), "a poll queue registers no completion callback");
    assert_eq!(plan.msix_vec, VIRTIO_MSI_NO_VECTOR);
    assert!(plan.map_notify, "a poller still has to kick the queue");
    assert!(profile.msix0_handler.is_some(), "the default queue keeps its interrupt");
    assert!(!profile.child_requirements.required_queues[POLL_QUEUE_INDEX as usize]);
    assert!(profile.child_requirements.optional_queues[POLL_QUEUE_INDEX as usize]);
}
