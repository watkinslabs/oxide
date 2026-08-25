use super::*;

#[test]
fn transport_profile_requires_event_status_and_device_config() {
    let _devices = crate::registry::own_device_table();
    let profile = crate::transport_profile();
    assert!(profile.child_requirements.required_queues[EVENT_QUEUE_SLOT]);
    assert!(profile.child_requirements.required_queues[STATUS_QUEUE_SLOT]);
    assert!(profile.child_requirements.needs_device_cfg);
    let q1 = profile.queue_plans[STATUS_QUEUE_SLOT].expect("statusq plan");
    assert_eq!(q1.index, STATUS_QUEUE_INDEX);
    assert!(q1.map_notify);
    assert_eq!(
        q1.msix_handler.is_some(),
        profile.q0_handler.is_some(),
    );
}

#[test]
fn resource_gate_rejects_missing_statusq_or_device_config() {
    let _devices = crate::registry::own_device_table();
    const QUEUE_SIZE: u16 = 2;
    const EVENT_DESC_PA: u64 = 1;
    const EVENT_DRIVER_PA: u64 = 2;
    const EVENT_DEVICE_PA: u64 = 3;
    const EVENT_NOTIFY_VA: u64 = 4;
    const STATUS_DESC_PA: u64 = 5;
    const STATUS_DRIVER_PA: u64 = 6;
    const STATUS_DEVICE_PA: u64 = 7;
    const STATUS_NOTIFY_VA: u64 = 8;
    const CFG_VA: u64 = 9;
    const HHDM: u64 = 10;
    const DEVICE_CFG_VA: u64 = 11;

    let q0 = virtio::VirtQueueResource::new(EVENT_QUEUE_INDEX, QUEUE_SIZE,
        EVENT_DESC_PA, EVENT_DRIVER_PA, EVENT_DEVICE_PA, EVENT_NOTIFY_VA, 0);
    let q1 = virtio::VirtQueueResource::new(STATUS_QUEUE_INDEX, QUEUE_SIZE,
        STATUS_DESC_PA, STATUS_DRIVER_PA, STATUS_DEVICE_PA, STATUS_NOTIFY_VA, 0);
    let no_q1 = virtio::VirtioResources::from_queues(CFG_VA, HHDM, &[q0])
        .with_device_cfg_va(DEVICE_CFG_VA);
    let no_device_cfg = virtio::VirtioResources::from_queues(CFG_VA, HHDM, &[q0, q1]);
    let complete = no_device_cfg.with_device_cfg_va(DEVICE_CFG_VA);

    assert!(queue::required_queues(&no_q1).is_none());
    assert!(queue::required_queues(&no_device_cfg).is_none());
    assert_eq!(queue::required_queues(&complete), Some((q0, q1)));
}


