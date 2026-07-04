    use super::*;
    use alloc::vec;
    use std::sync::{Arc, Mutex};

    #[test]
    fn child_driver_id_matches_virtio_child_devices() {
        let id = VirtioChildDriverId::new("virtio-test", 42);

        assert_eq!(id.name, "virtio-test");
        assert!(id.matches_device(VIRTIO_CHILD_BUS, VIRTIO_VENDOR_ID, 42));
        assert!(!id.matches_device("pci", VIRTIO_VENDOR_ID, 42));
        assert!(!id.matches_device(VIRTIO_CHILD_BUS, 0x1234, 42));
        assert!(!id.matches_device(VIRTIO_CHILD_BUS, VIRTIO_VENDOR_ID, 43));
    }

    #[test]
    fn child_model_identity_maps_modern_pci_device() {
        let child = VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x1041, 2)
            .expect("modern virtio block id");

        assert_eq!(child.bus, VIRTIO_CHILD_BUS);
        assert_eq!(child.addr, "virtio2");
        assert_eq!(child.vendor_id, 0x1AF4);
        assert_eq!(child.device_id, 1);
        assert_eq!(child.class, VIRTIO_CHILD_CLASS);
    }

    #[test]
    fn child_model_identity_rejects_non_modern_pci_device() {
        assert!(VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x1000, 0).is_none());
        assert!(VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x9999, 0).is_none());
    }

    #[test]
    fn child_parent_match_requires_virtio_bus_and_matching_parent() {
        assert!(virtio_child_has_parent(
            VIRTIO_CHILD_BUS,
            Some(("pci", "0000:00:01.0")),
            "pci",
            "0000:00:01.0",
        ));
        assert!(!virtio_child_has_parent(
            "pci",
            Some(("pci", "0000:00:01.0")),
            "pci",
            "0000:00:01.0",
        ));
        assert!(!virtio_child_has_parent(
            VIRTIO_CHILD_BUS,
            Some(("pci", "0000:00:02.0")),
            "pci",
            "0000:00:01.0",
        ));
        assert!(!virtio_child_has_parent(
            VIRTIO_CHILD_BUS,
            None,
            "pci",
            "0000:00:01.0",
        ));
    }

    #[test]
    fn child_device_key_is_constructed_from_transport_location() {
        let location = VirtioTransportLocation::new(0x12, 0x03, 0x04);
        let key = VirtioChildDeviceKey::from_location(location);

        assert_eq!(key.raw(), 0x0012_0304);
        assert_eq!(VirtioChildDeviceKey::from_raw(0x0012_0304), key);
    }

    #[test]
    fn probe_lease_take_is_idempotent() {
        let mut lease = VirtioProbeLease::live();

        assert!(lease.is_live());
        assert!(lease.take());
        assert!(!lease.is_live());
        assert!(!lease.take());
    }

    #[test]
    fn default_probe_lease_is_empty() {
        let mut lease = VirtioProbeLease::default();

        assert!(!lease.is_live());
        assert!(!lease.take());
    }

    #[derive(Default)]
    struct ProbeLifecycle {
        published: bool,
        released: bool,
    }

    struct ProbeSession {
        lifecycle: Arc<Mutex<ProbeLifecycle>>,
    }

    impl ProbeSession {
        fn new(lifecycle: Arc<Mutex<ProbeLifecycle>>) -> Self {
            Self { lifecycle }
        }
    }

    impl VirtioChildTransportSession for ProbeSession {
        fn device_key(&self) -> VirtioChildDeviceKey {
            VirtioChildDeviceKey::from_raw(1)
        }

        fn location(&self) -> VirtioTransportLocation {
            VirtioTransportLocation::new(0, 1, 0)
        }

        fn device_addr(&self) -> &str {
            "virtio-test0"
        }

        fn drv_features(&self) -> u64 {
            0
        }

        fn net_boot_payloads(&self) -> VirtioNetBootPayloads {
            VirtioNetBootPayloads::default()
        }

        fn child_resources(&self) -> Option<VirtioResources> {
            None
        }

        fn release_failed_child(&mut self) {
            self.lifecycle.lock().unwrap().released = true;
        }

        fn publish(self) {
            self.lifecycle.lock().unwrap().published = true;
        }
    }

    #[test]
    fn child_probe_lifecycle_publishes_only_after_success() {
        let lifecycle = Arc::new(Mutex::new(ProbeLifecycle::default()));
        let result = run_child_probe(ProbeSession::new(lifecycle.clone()), |session| {
            assert_eq!(session.device_key().raw(), 1);
            Ok::<(), ()>(())
        });

        assert_eq!(result, Ok(()));
        let lifecycle = lifecycle.lock().unwrap();
        assert!(lifecycle.published);
        assert!(!lifecycle.released);
    }

    #[test]
    fn child_probe_lifecycle_releases_on_child_error() {
        let lifecycle = Arc::new(Mutex::new(ProbeLifecycle::default()));
        let result = run_child_probe(ProbeSession::new(lifecycle.clone()), |_session| {
            Err::<(), u8>(7)
        });

        assert_eq!(result, Err(7));
        let lifecycle = lifecycle.lock().unwrap();
        assert!(!lifecycle.published);
        assert!(lifecycle.released);
    }

    #[test]
    fn child_remove_lifecycle_removes_before_unpublish() {
        let key = VirtioChildDeviceKey::from_raw(0x12);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let remove_calls = calls.clone();
        let unpublish_calls = calls.clone();

        run_child_remove(
            key,
            |device_key| remove_calls.lock().unwrap().push(("remove", device_key.raw())),
            |device_key| {
                unpublish_calls
                    .lock()
                    .unwrap()
                    .push(("unpublish", device_key.raw()))
            },
        );

        assert_eq!(
            *calls.lock().unwrap(),
            vec![("remove", 0x12), ("unpublish", 0x12)]
        );
    }

    #[test]
    fn child_shutdown_lifecycle_passes_stable_key() {
        let key = VirtioChildDeviceKey::from_raw(0x34);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let shutdown_calls = calls.clone();

        run_child_shutdown(key, |device_key| {
            shutdown_calls.lock().unwrap().push(device_key.raw())
        });

        assert_eq!(*calls.lock().unwrap(), vec![0x34]);
    }

    const VALID_Q0: VirtQueueResource = VirtQueueResource {
        index:      0,
        size:       8,
        desc_pa:    0x1000,
        driver_pa:  0x2000,
        device_pa:  0x3000,
        notify_va:  0x4000,
        notify_off: 2,
    };

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
        let scanned = [
            (0, 8),
            (3, 16),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ];

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
            QueueRing {
                desc_pa: 0x1000,
                driver_pa: 0x2000,
                device_pa: 0x3000,
                notify_off: 4,
                size: 8,
            },
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
        let scanned = [
            (0, 8),
            (1, 16),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ];
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
        assert_eq!(
            handoff.net_boot_payloads,
            VirtioNetBootPayloads::new(0x7000, 64, 0x8000)
        );
    }

    #[test]
    fn resolve_planned_notify_mappings_uses_child_queue_policy() {
        let programmed = ProgrammedQueues::from_test_parts(
            QueueRing {
                desc_pa: 0x1000,
                driver_pa: 0x2000,
                device_pa: 0x3000,
                notify_off: 4,
                size: 8,
            },
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

        let mut state =
            VirtioChildResourceState::new(crate::VIRTIO_STATUS_DRIVER_OK, 0x10, 0x20);
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
        assert!(facts
            .resources_for_child(VirtioChildRequirements::q0())
            .is_some());
    }

    #[test]
    fn transport_probe_result_builds_child_facts_and_frame_lists() {
        let mut queues = core::array::from_fn(|index| {
            VirtQueueResource::new(index as u16, 0, 0, 0, 0, 0, 0)
        });
        queues[0] = VALID_Q0;
        queues[1] = VirtQueueResource {
            index:      1,
            size:       8,
            desc_pa:    0x5000,
            driver_pa:  0x6000,
            device_pa:  0x7000,
            notify_va:  0x8000,
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

        assert_eq!(
            result.vring_frames(),
            alloc::vec![0x1000, 0x2000, 0x3000, 0x5000, 0x6000, 0x7000]
        );
        assert_eq!(result.net_payload_frames(), alloc::vec![0x9000, 0xa000]);
    }

    #[test]
    fn owned_probe_frames_drain_all_failed_probe_resources_once() {
        let mut queues = core::array::from_fn(|index| {
            VirtQueueResource::new(index as u16, 0, 0, 0, 0, 0, 0)
        });
        queues[0] = VirtQueueResource {
            index:      0,
            size:       8,
            desc_pa:    0x1000,
            driver_pa:  0x2000,
            device_pa:  0x3000,
            notify_va:  0x4000,
            notify_off: 2,
        };
        queues[1] = VirtQueueResource {
            index:      1,
            size:       8,
            desc_pa:    0x1000,
            driver_pa:  0x5000,
            device_pa:  0x6000,
            notify_va:  0x7000,
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

        assert_eq!(
            owned.take_all(),
            alloc::vec![0x1000, 0x2000, 0x3000, 0x5000, 0x6000, 0x8000]
        );
        assert!(owned.is_empty());
        assert!(owned.take_all().is_empty());
    }

    #[test]
    fn owned_probe_frames_publish_only_transfers_vring_frames() {
        let mut queues = core::array::from_fn(|index| {
            VirtQueueResource::new(index as u16, 0, 0, 0, 0, 0, 0)
        });
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
