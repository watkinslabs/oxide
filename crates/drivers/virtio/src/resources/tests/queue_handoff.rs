use super::*;

#[test]
fn require_queue_accepts_matching_runtime_queue() {
    let resources = VirtioResources::from_queues(0x10, 0x20, &[VALID_Q0]);

    assert_eq!(resources.require_queue(0), Some(VALID_Q0));
    assert!(resources.require_common_and_queues(&[0]));
}

#[test]
fn require_queue_rejects_missing_or_invalid_queue() {
    let mut invalid = VALID_Q0;
    invalid.notify_va = 0;
    let resources = VirtioResources::from_queues(0x10, 0x20, &[invalid]);

    assert_eq!(resources.require_queue(0), None);
    assert_eq!(resources.require_queue(1), None);
    assert!(!resources.require_common_and_queues(&[0]));
    assert!(!resources.require_common_and_queues(&[1]));
}

#[test]
fn require_common_and_queues_rejects_missing_common_state() {
    let resources = VirtioResources::from_queues(0, 0x20, &[VALID_Q0]);

    assert_eq!(resources.require_queue(0), Some(VALID_Q0));
    assert!(!resources.require_common_and_queues(&[0]));
}

#[test]
fn notify_mappings_are_indexed_and_bounded() {
    let mut mappings = VirtioQueueNotifyMappings::new();
    mappings.set(1, 0x1000);
    mappings.set((MAX_RESOURCE_QUEUES + 1) as u16, 0x2000);

    assert_eq!(mappings.get(1), 0x1000);
    assert_eq!(mappings.get((MAX_RESOURCE_QUEUES + 1) as u16), 0);
}

#[test]
fn build_queue_resources_uses_scanned_sizes_and_notify_mappings() {
    let mut mappings = VirtioQueueNotifyMappings::new();
    mappings.set(0, 0x1000);
    mappings.set(3, 0x3000);
    let scanned = [(0, 8), (3, 16), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0)];

    let resources = build_queue_resources(&scanned, 2, None, &mappings);

    assert_eq!(resources[0].index, 0);
    assert_eq!(resources[0].size, 8);
    assert_eq!(resources[0].notify_va, 0x1000);
    assert_eq!(resources[3].index, 3);
    assert_eq!(resources[3].size, 16);
    assert_eq!(resources[3].notify_va, 0x3000);
    assert_eq!(resources[2].size, 0);
}

#[test]
fn build_runtime_handoff_applies_final_notify_observations() {
    let programmed = ProgrammedQueues::from_test_parts(
        QueueRing { desc_pa: 0x1000, driver_pa: 0x2000, device_pa: 0x3000, notify_off: 4, size: 8 },
        core::array::from_fn(|index| {
            if index == 1 {
                Some(QueueRing {
                    desc_pa: 0x4000,
                    driver_pa: 0x5000,
                    device_pa: 0x6000,
                    notify_off: 8,
                    size: 16,
                })
            } else {
                None
            }
        }),
    );
    let scanned = [(0, 8), (1, 16), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0)];
    let mut planned = VirtioQueueNotifyMappings::new();
    planned.set(1, 0x1111);

    let handoff = build_runtime_handoff(VirtioRuntimeHandoffInput {
        scanned_queues: &scanned,
        scanned_len: 2,
        programmed_queues: Some(&programmed),
        planned_notify_mappings: planned,
        q0_notify_va: 0xaaa0,
        q1_notify_va: 0xbbb0,
        post_notify_status: crate::VIRTIO_STATUS_DRIVER_OK,
        avail_idx_posted: 1,
        used_idx_observed: 2,
        isr_status: 3,
        net_boot_payloads: VirtioNetBootPayloads::new(0x7000, 64, 0x8000),
    });

    assert_eq!(handoff.queue_resources[0].size, 8);
    assert_eq!(handoff.queue_resources[0].notify_va, 0xaaa0);
    assert_eq!(handoff.queue_resources[1].size, 16);
    assert_eq!(handoff.queue_resources[1].notify_va, 0xbbb0);
    assert_eq!(handoff.queue_resources[1].desc_pa, 0x4000);
    assert_eq!(handoff.post_notify_status, crate::VIRTIO_STATUS_DRIVER_OK);
    assert_eq!(handoff.avail_idx_posted, 1);
    assert_eq!(handoff.used_idx_observed, 2);
    assert_eq!(handoff.isr_status, 3);
    assert_eq!(handoff.net_boot_payloads, VirtioNetBootPayloads::new(0x7000, 64, 0x8000));
}

#[test]
fn resolve_planned_notify_mappings_uses_child_queue_policy() {
    let programmed = ProgrammedQueues::from_test_parts(
        QueueRing { desc_pa: 0x1000, driver_pa: 0x2000, device_pa: 0x3000, notify_off: 4, size: 8 },
        core::array::from_fn(|index| {
            if index == 1 {
                Some(QueueRing {
                    desc_pa: 0x4000,
                    driver_pa: 0x5000,
                    device_pa: 0x6000,
                    notify_off: 8,
                    size: 8,
                })
            } else if index == 2 {
                Some(QueueRing {
                    desc_pa: 0x7000,
                    driver_pa: 0x8000,
                    device_pa: 0x9000,
                    notify_off: 12,
                    size: 8,
                })
            } else {
                None
            }
        }),
    );
    let mut plans = [None; MAX_RESOURCE_QUEUES];
    plans[1] = Some(VirtioQueuePlan::new(1, None, true));
    plans[2] = Some(VirtioQueuePlan::new(2, None, false));
    plans[3] = Some(VirtioQueuePlan::new(3, None, true));

    let mappings = resolve_planned_notify_mappings(&plans, Some(&programmed), |notify_off| {
        0x1000 + notify_off as u64
    });

    assert_eq!(mappings.get(1), 0x1008);
    assert_eq!(mappings.get(2), 0);
    assert_eq!(mappings.get(3), 0);
}

#[test]
fn child_requirements_describe_transport_contracts() {
    let q0 = VirtioChildRequirements::q0();
    assert!(q0.required_queues[0]);
    assert!(!q0.needs_device_cfg);
    assert!(!q0.needs_net_boot_payloads);

    let net = VirtioChildRequirements::net();
    assert!(net.required_queues[0]);
    assert!(net.required_queues[1]);
    assert!(net.needs_net_boot_payloads);
    assert!(!net.needs_device_cfg);

    let snd = VirtioChildRequirements::snd();
    assert!(snd.required_queues[0]);
    assert!(snd.required_queues[1]);
    assert!(snd.required_queues[2]);
    assert!(snd.required_queues[3]);
    assert!(snd.needs_device_cfg);
    assert!(!snd.required_queues[4]);
}

#[test]
fn transport_profiles_describe_child_queue_policy() {
    let net = VirtioTransportProfile::net(0x55, None);
    assert_eq!(net.drv_features, 0x55);
    assert_eq!(net.early_payload_policy, VirtioEarlyPayloadPolicy::Net);
    assert_eq!(net.queue_plans[1].map(|q| q.index), Some(1));
    assert!(net.queue_plans[1].map(|q| q.map_notify).unwrap_or(false));
    assert!(net.child_requirements.needs_net_boot_payloads);

    let snd = VirtioTransportProfile::snd(0xaa, None, None);
    assert_eq!(snd.drv_features, 0xaa);
    assert_eq!(snd.queue_plans[1].map(|q| q.index), Some(1));
    assert_eq!(snd.queue_plans[2].map(|q| q.index), Some(2));
    assert_eq!(snd.queue_plans[3].map(|q| q.index), Some(3));
    assert!(snd.queue_plans[1].map(|q| q.map_notify).unwrap_or(false));
    assert!(snd.queue_plans[2].map(|q| q.map_notify).unwrap_or(false));
    assert_eq!(snd.early_payload_policy, VirtioEarlyPayloadPolicy::None);
    assert!(snd.child_requirements.needs_device_cfg);
}

#[test]
fn child_session_data_is_transport_neutral() {
    let loc = VirtioTransportLocation::new(0, 3, 1);
    assert_eq!(loc.bus, 0);
    assert_eq!(loc.device, 3);
    assert_eq!(loc.function, 1);

    let empty = VirtioNetBootPayloads::default();
    assert!(!empty.is_present());

    let payloads = VirtioNetBootPayloads::new(0x1000, 64, 0x2000);
    assert!(payloads.is_present());
}
