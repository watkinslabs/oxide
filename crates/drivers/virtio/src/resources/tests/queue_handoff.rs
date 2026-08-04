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
fn require_queue_rejects_a_ring_larger_than_its_backing_frame() {
    let mut oversized = VALID_Q0;
    oversized.size = crate::queue_cfg::MAX_QUEUE_SIZE + 1;
    let resources = VirtioResources::from_queues(0x10, 0x20, &[oversized]);

    assert_eq!(resources.require_queue(0), None);
    assert!(!resources.require_common_and_queues(&[0]));
}

#[test]
fn require_queue_at_least_rejects_a_too_small_protocol_ring() {
    let resources = VirtioResources::from_queues(0x10, 0x20, &[VALID_Q0]);

    assert_eq!(resources.require_queue_at_least(0, VALID_Q0.size), Some(VALID_Q0));
    assert_eq!(resources.require_queue_at_least(0, VALID_Q0.size + 1), None);
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
    planned.set(1, 0xbbb0);

    let handoff = build_runtime_handoff(VirtioRuntimeHandoffInput {
        scanned_queues: &scanned,
        scanned_len: 2,
        programmed_queues: Some(&programmed),
        planned_notify_mappings: planned,
        q0_notify_va: 0xaaa0,
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
    assert!(net.needs_device_cfg);

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
    assert!(net.child_requirements.needs_device_cfg);

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
fn queue_plans_default_to_named_no_vector_sentinel() {
    let plan = VirtioQueuePlan::new(1, None, true);
    assert_eq!(plan.msix_vec, VIRTIO_MSI_NO_VECTOR);
    assert_eq!(plan.with_msix_vec(2).msix_vec, 2);

    let net = VirtioTransportProfile::net(0x55, None);
    assert_eq!(net.queue_plans[1].map(|q| q.msix_vec), Some(VIRTIO_MSI_NO_VECTOR));

    let snd = VirtioTransportProfile::snd(0xaa, None, None);
    assert_eq!(snd.queue_plans[1].map(|q| q.msix_vec), Some(VIRTIO_MSI_NO_VECTOR));
    assert_eq!(snd.queue_plans[2].map(|q| q.msix_vec), Some(VIRTIO_MSI_NO_VECTOR));
    assert_eq!(snd.queue_plans[3].map(|q| q.msix_vec), Some(VIRTIO_MSI_NO_VECTOR));
}

fn fake_config_irq() {}
fn fake_event_irq() {}

fn same_fn(left: Option<fn()>, right: fn()) -> bool {
    left.map(|f| core::ptr::fn_addr_eq(f, right)).unwrap_or(false)
}

#[test]
fn transport_profiles_carry_child_declared_msix_handlers() {
    let net = VirtioTransportProfile::net(0x55, Some(fake_config_irq));
    assert!(same_fn(net.msix0_handler, fake_config_irq));
    assert!(net.queue_plans[1].and_then(|q| q.msix_handler).is_none());

    let input = VirtioTransportProfile::q0_device_cfg(0x66, Some(fake_config_irq));
    assert!(same_fn(input.msix0_handler, fake_config_irq));
    assert!(input.queue_plans.iter().all(|plan| plan.is_none()));

    let snd = VirtioTransportProfile::snd(0x77, None, Some(fake_event_irq));
    assert!(snd.msix0_handler.is_none());
    assert!(same_fn(snd.queue_plans[1].and_then(|q| q.msix_handler), fake_event_irq));
    assert!(snd.queue_plans[2].and_then(|q| q.msix_handler).is_none());
    assert!(snd.queue_plans[3].and_then(|q| q.msix_handler).is_none());

    let rng = VirtioTransportProfile::q0(0x88, None);
    assert!(rng.msix0_handler.is_none());
    assert!(rng.queue_plans.iter().all(|plan| plan.is_none()));
}

#[test]
fn snd_eventq_plan_carries_child_irq_and_notify_mapping() {
    const CONTROLQ: u16 = 0;
    const EVENTQ: u16 = 1;
    const TXQ: u16 = 2;
    const RXQ: u16 = 3;
    const QUEUE_SIZE: u16 = 8;
    const NOTIFY_BASE: u64 = 0x1000;
    const EVENT_NOTIFY_OFF: u16 = 8;
    const TX_NOTIFY_OFF: u16 = 12;
    const RX_NOTIFY_OFF: u16 = 16;
    const Q0_NOTIFY_VA: u64 = 0x2000;
    const TEST_FEATURES: u64 = 0x77;
    const Q0_NOTIFY_OFF: u16 = 4;
    const Q0_DESC_PA: u64 = 0x1000;
    const Q0_DRIVER_PA: u64 = 0x2000;
    const Q0_DEVICE_PA: u64 = 0x3000;
    const EVENT_DESC_PA: u64 = 0x4000;
    const EVENT_DRIVER_PA: u64 = 0x5000;
    const EVENT_DEVICE_PA: u64 = 0x6000;
    const TX_DESC_PA: u64 = 0x7000;
    const TX_DRIVER_PA: u64 = 0x8000;
    const TX_DEVICE_PA: u64 = 0x9000;
    const RX_DESC_PA: u64 = 0xa000;
    const RX_DRIVER_PA: u64 = 0xb000;
    const RX_DEVICE_PA: u64 = 0xc000;

    let profile = VirtioTransportProfile::snd(TEST_FEATURES, None, Some(fake_event_irq));
    assert!(same_fn(profile.queue_plans[EVENTQ as usize].and_then(|q| q.msix_handler), fake_event_irq));
    assert!(profile.queue_plans[TXQ as usize].and_then(|q| q.msix_handler).is_none());
    assert!(profile.queue_plans[RXQ as usize].and_then(|q| q.msix_handler).is_none());

    let programmed = ProgrammedQueues::from_test_parts(
        QueueRing {
            desc_pa: Q0_DESC_PA, driver_pa: Q0_DRIVER_PA, device_pa: Q0_DEVICE_PA,
            notify_off: Q0_NOTIFY_OFF, size: QUEUE_SIZE,
        },
        core::array::from_fn(|index| match index as u16 {
            EVENTQ => Some(QueueRing {
                desc_pa: EVENT_DESC_PA, driver_pa: EVENT_DRIVER_PA, device_pa: EVENT_DEVICE_PA,
                notify_off: EVENT_NOTIFY_OFF, size: QUEUE_SIZE,
            }),
            TXQ => Some(QueueRing {
                desc_pa: TX_DESC_PA, driver_pa: TX_DRIVER_PA, device_pa: TX_DEVICE_PA,
                notify_off: TX_NOTIFY_OFF, size: QUEUE_SIZE,
            }),
            RXQ => Some(QueueRing {
                desc_pa: RX_DESC_PA, driver_pa: RX_DRIVER_PA, device_pa: RX_DEVICE_PA,
                notify_off: RX_NOTIFY_OFF, size: QUEUE_SIZE,
            }),
            _ => None,
        }),
    );
    let scanned = [(CONTROLQ, QUEUE_SIZE), (EVENTQ, QUEUE_SIZE), (TXQ, QUEUE_SIZE), (RXQ, QUEUE_SIZE), (0, 0), (0, 0), (0, 0), (0, 0)];
    let planned = resolve_planned_notify_mappings(&profile.queue_plans, Some(&programmed), |notify_off| {
        NOTIFY_BASE + notify_off as u64
    });

    let handoff = build_runtime_handoff(VirtioRuntimeHandoffInput {
        scanned_queues: &scanned,
        scanned_len: RXQ as usize + 1,
        programmed_queues: Some(&programmed),
        planned_notify_mappings: planned,
        q0_notify_va: Q0_NOTIFY_VA,
        post_notify_status: crate::VIRTIO_STATUS_DRIVER_OK,
        avail_idx_posted: 0,
        used_idx_observed: 0,
        isr_status: 0,
        net_boot_payloads: VirtioNetBootPayloads::default(),
    });

    assert_eq!(handoff.queue_resources[EVENTQ as usize].index, EVENTQ);
    assert_eq!(handoff.queue_resources[EVENTQ as usize].notify_va, NOTIFY_BASE + EVENT_NOTIFY_OFF as u64);
    assert_eq!(handoff.queue_resources[TXQ as usize].notify_va, NOTIFY_BASE + TX_NOTIFY_OFF as u64);
    assert_eq!(handoff.queue_resources[RXQ as usize].notify_va, NOTIFY_BASE + RX_NOTIFY_OFF as u64);
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
