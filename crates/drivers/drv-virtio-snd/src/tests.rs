use super::*;
mod drain;
mod prepost;
    use core::sync::atomic::AtomicU64;

    static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());
    static TEST_EVENT_CALLS: AtomicU64 = AtomicU64::new(0);
    const PROBE_FRAME_BASE: u64 = 0x0100;
    const DISARMED_FRAME_BASE: u64 = 0x0200;
    const FAILED_SCAN_FRAME_BASE: u64 = 0x0300;
    const SND_TEARDOWN_KEY: u32 = 0x0080_0000;
    const SND_FAILED_SCAN_KEY: u32 = 0x0090_0000;

    const fn key(raw: u32) -> DeviceKey {
        DeviceKey::from_raw(raw)
    }

    fn test_event_handler() {
        TEST_EVENT_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn get_u16(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_event(buf: &mut [u8], desc_id: usize, value: u64) {
        let off = desc_id * EVENT_SIZE;
        buf[off..off + EVENT_SIZE].copy_from_slice(&value.to_le_bytes());
    }

    fn queue(index: u16) -> virtio::VirtQueueResource {
        virtio::VirtQueueResource {
            index,
            size: 8,
            desc_pa: 0,
            driver_pa: 0,
            device_pa: 0,
            notify_va: 0,
            notify_off: 0,
        }
    }

    fn ctx(device_key: DeviceKey) -> Ctx {
        Ctx {
            device_key,
            controlq: queue(0),
            hhdm: 0,
            cfg_va: 0,
            scratch_pa: 0,
            avail_idx: 0,
            eventq: Some(queue(1)),
            event_buf_pa: 0,
            event_last_used: 0,
            event_avail_idx: 0,
            event_drained: 0,
            event_last_raw: 0,
            jacks: 0,
            streams: 0,
            chmaps: 0,
            controls: 0,
            out_stream: None,
            out_formats: 0,
            out_rates: 0,
            out_ch_min: 1,
            out_ch_max: 2,
            txq: None,
            tx_avail_idx: 0,
            tx_buf_pa: 0,
            tx_scratch_pa: 0,
            pcm_state: PcmState::Idle,
            cfg_rate: VIRTIO_SND_PCM_RATE_44100,
            cfg_format: VIRTIO_SND_PCM_FMT_S16,
            cfg_channels: 2,
            cfg_period_bytes: PERIOD_BYTES as u32,
            in_stream: None,
            in_formats: 0,
            in_rates: 0,
            in_ch_min: 1,
            in_ch_max: 2,
            rxq: None,
            rx_avail_idx: 0,
            rx_buf_pa: 0,
            rx_scratch_pa: 0,
            cap_state: PcmState::Idle,
            cap_rate: VIRTIO_SND_PCM_RATE_44100,
            cap_format: VIRTIO_SND_PCM_FMT_S16,
            cap_channels: 2,
            cap_period_bytes: PERIOD_BYTES as u32,
        }
    }

    fn ctx_with_test_frames(device_key: DeviceKey, base: u64) -> Ctx {
        let mut c = ctx(device_key);
        c.scratch_pa = test_frame_pa(base);
        c.event_buf_pa = test_frame_pa(base + 1);
        c.tx_buf_pa = test_frame_pa(base + 2);
        c.tx_scratch_pa = test_frame_pa(base + 3);
        c.rx_buf_pa = test_frame_pa(base + 4);
        c.rx_scratch_pa = test_frame_pa(base + 5);
        c.txq = Some(queue(2));
        c.rxq = Some(queue(3));
        c
    }

    fn probe_frame_set(base: u64) -> [u64; 6] {
        [
            test_frame_pa(base),
            test_frame_pa(base + 1),
            test_frame_pa(base + 2),
            test_frame_pa(base + 3),
            test_frame_pa(base + 4),
            test_frame_pa(base + 5),
        ]
    }

    fn stop_free_order(base: u64) -> [u64; 6] {
        [
            test_frame_pa(base + 1),
            test_frame_pa(base + 4),
            test_frame_pa(base + 5),
            test_frame_pa(base + 2),
            test_frame_pa(base + 3),
            test_frame_pa(base),
        ]
    }

    fn reset_test_state() {
        CTX.lock().clear();
        clear_freed_frames_for_tests();
        TEST_EVENT_CALLS.store(0, Ordering::Relaxed);
        DRAINED_EVENTS.store(0, Ordering::Relaxed);
        LAST_EVENT.store(0, Ordering::Relaxed);
        let _ = softirq::clear_handler(softirq::Slot::SndEvent);
    }

    fn owner_key(device_key: DeviceKey) -> sound::SoundOwnerKey {
        sound_owner(device_key).expect("test device key must map to sound owner")
    }

    /// `prepost_eventq` writes one 16-byte descriptor AND one EVENT_SIZE
    /// buffer per accepted eventq slot, each into a single frame. The install
    /// cap must therefore respect BOTH frames: sizing it from the event
    /// buffers alone lets a device advertise a queue whose descriptor writes
    /// run off the end of the descriptor frame.
    #[test]
    fn accepted_eventq_size_fits_the_descriptor_frame_as_well_as_the_event_frame() {
        let descs = MAX_EVENTQ_DESCS as usize;

        assert!(descs * crate::lifecycle::VIRTQ_DESC_ENTRY_BYTES <= SND_FRAME_BYTES);
        assert!(descs * EVENT_SIZE <= SND_FRAME_BYTES);
        assert!(descs > 0);
    }

    #[test]
    fn transport_profile_carries_child_feature_mask() {
        let profile = transport_profile();

        assert_eq!(profile.drv_features, wanted_features());
        assert_eq!(profile.drv_features, virtio::VIRTIO_F_VERSION_1);
        assert!(profile.child_requirements.needs_device_cfg);
        assert!(profile.child_requirements.required_queues[0]);
        assert!(profile.child_requirements.required_queues[1]);
        assert!(profile.child_requirements.required_queues[2]);
        assert!(profile.child_requirements.required_queues[3]);
        assert!(profile.child_requirements.required_queues[4..].iter().all(|required| !required));
    }

    #[test]
    fn snd_config_reads_generic_device_config_resource() {
        const TEST_CFG_VA: u64 = 0x1000;
        const TEST_HHDM: u64 = 0x2000;
        const TEST_SND_CONFIG: (u32, u32, u32, u32) = (3, 4, 5, 6);
        let cfg = [
            TEST_SND_CONFIG.0,
            TEST_SND_CONFIG.1,
            TEST_SND_CONFIG.2,
            TEST_SND_CONFIG.3,
        ];
        let resources = virtio::VirtioResources::new(TEST_CFG_VA, TEST_HHDM)
            .with_device_cfg_va(cfg.as_ptr() as u64);
        let got = lifecycle::read_device_config(resources).unwrap();

        assert_eq!((got.jacks, got.streams, got.chmaps, got.controls), TEST_SND_CONFIG);
        assert!(lifecycle::read_device_config(virtio::VirtioResources::new(TEST_CFG_VA, TEST_HHDM)).is_none());
    }

    fn publish_test_card(owner: sound::SoundOwnerKey) {
        let _ = sound::unregister_card(owner);
        let _ = sound::ops::clear(owner);
        assert!(sound::reserve_card(owner));
        assert!(sound::ops::register(owner, &SOUND_OPS));
        assert!(sound::register_card(owner));
        assert!(sound::card_number(owner).is_some());
        assert!(sound::ops::ops_for(owner).is_some());
    }

    #[test]
    fn event_stats_are_keyed_by_snd_context() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        {
            let mut ctxs = CTX.lock();
            ctxs.push(ctx(key(0x0010_0000)));
            ctxs.push(ctx(key(0x0020_0000)));
            record_event(&mut ctxs[0], 0xaaaa_0000_0000_0001);
            record_event(&mut ctxs[1], 0xbbbb_0000_0000_0002);
            record_event(&mut ctxs[1], 0xbbbb_0000_0000_0003);
        }

        assert_eq!(event_stats_for(key(0x0010_0000)), Some((1, 0xaaaa_0000_0000_0001)));
        assert_eq!(event_stats_for(key(0x0020_0000)), Some((2, 0xbbbb_0000_0000_0003)));
        assert_eq!(event_stats_for(key(0x0030_0000)), None);
        assert_eq!(DRAINED_EVENTS.load(Ordering::Relaxed), 3);
        assert_eq!(LAST_EVENT.load(Ordering::Relaxed), 0xbbbb_0000_0000_0003);
        assert_eq!(eventq_state_for(key(0x0010_0000)), Some((8, 0, 0)));
        assert_eq!(eventq_state_for(key(0x0020_0000)), Some((8, 0, 0)));
        reset_test_state();
    }

    #[test]
    fn caps_exist_only_for_scanned_stream_directions() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let owner = owner_key(key(0x0010_0000));
        let mut c = ctx(key(0x0010_0000));
        CTX.lock().push(c);
        assert!(pcm_caps(owner).is_none());
        assert!(cap_caps(owner).is_none());

        c = remove_ctx(key(0x0010_0000)).expect("context must be present").0;
        c.out_stream = Some(0);
        c.out_formats = 1 << VIRTIO_SND_PCM_FMT_S16;
        c.out_rates = 1 << VIRTIO_SND_PCM_RATE_44100;
        CTX.lock().push(c);
        assert_eq!(
            pcm_caps(owner),
            Some((1 << VIRTIO_SND_PCM_FMT_S16, 1 << VIRTIO_SND_PCM_RATE_44100, 1, 2))
        );
        assert!(cap_caps(owner).is_none());

        c = remove_ctx(key(0x0010_0000)).expect("context must be present").0;
        c.in_stream = Some(1);
        c.in_formats = 1 << VIRTIO_SND_PCM_FMT_S16;
        c.in_rates = 1 << VIRTIO_SND_PCM_RATE_44100;
        CTX.lock().push(c);
        assert_eq!(
            cap_caps(owner),
            Some((1 << VIRTIO_SND_PCM_FMT_S16, 1 << VIRTIO_SND_PCM_RATE_44100, 1, 2))
        );
        reset_test_state();
    }

    #[test]
    fn removing_one_snd_context_keeps_event_softirq_installed() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        {
            let mut ctxs = CTX.lock();
            ctxs.push(ctx(key(0x0010_0000)));
            ctxs.push(ctx(key(0x0020_0000)));
        }
        softirq::set_handler(softirq::Slot::SndEvent, test_event_handler);

        let removed = remove_ctx_and_release_event_handler(key(0x0010_0000))
            .expect("expected first context removal");
        assert_eq!(removed.device_key, key(0x0010_0000));
        softirq::raise(softirq::Slot::SndEvent);
        // SAFETY: hosted unit test owns the SndEvent slot under TEST_LOCK.
        unsafe { softirq::run_pending(); }
        assert_eq!(TEST_EVENT_CALLS.load(Ordering::Relaxed), 1);
        assert!(present_for(key(0x0020_0000)));
        reset_test_state();
    }

    #[test]
    fn removing_last_snd_context_clears_event_softirq() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        CTX.lock().push(ctx(key(0x0010_0000)));
        softirq::set_handler(softirq::Slot::SndEvent, test_event_handler);

        let removed = remove_ctx_and_release_event_handler(key(0x0010_0000))
            .expect("expected last context removal");
        assert_eq!(removed.device_key, key(0x0010_0000));
        softirq::raise(softirq::Slot::SndEvent);
        // SAFETY: hosted unit test owns the SndEvent slot under TEST_LOCK.
        unsafe { softirq::run_pending(); }
        assert_eq!(TEST_EVENT_CALLS.load(Ordering::Relaxed), 0);
        assert!(!present());
        reset_test_state();
    }

    #[test]
    fn probe_frames_drop_frees_all_owned_snd_frames() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        {
            let frames = SndProbeFrames::for_tests(PROBE_FRAME_BASE);
            assert_eq!(frames.all(), probe_frame_set(PROBE_FRAME_BASE));
        }
        assert_eq!(freed_frames_for_tests(), probe_frame_set(PROBE_FRAME_BASE));
        reset_test_state();
    }

    #[test]
    fn disarmed_probe_frames_wait_for_context_teardown() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        {
            let mut frames = SndProbeFrames::for_tests(DISARMED_FRAME_BASE);
            frames.disarm();
        }
        assert!(freed_frames_for_tests().is_empty());
        stop_reset_free(ctx_with_test_frames(key(SND_TEARDOWN_KEY), DISARMED_FRAME_BASE));
        assert_eq!(freed_frames_for_tests(), stop_free_order(DISARMED_FRAME_BASE));
        reset_test_state();
    }

    #[test]
    fn failed_scan_context_teardown_frees_snd_frames_and_clears_softirq() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let device_key = key(SND_FAILED_SCAN_KEY);
        CTX.lock().push(ctx_with_test_frames(device_key, FAILED_SCAN_FRAME_BASE));
        softirq::set_handler(softirq::Slot::SndEvent, test_event_handler);

        let Some(ctx) = remove_ctx_and_release_event_handler(device_key) else {
            panic!("expected failed-probe context removal");
        };
        stop_reset_free(ctx);
        softirq::raise(softirq::Slot::SndEvent);
        // SAFETY: hosted unit test owns the SndEvent slot under TEST_LOCK.
        unsafe { softirq::run_pending(); }

        assert_eq!(TEST_EVENT_CALLS.load(Ordering::Relaxed), 0);
        assert!(!present_for(device_key));
        assert_eq!(freed_frames_for_tests(), stop_free_order(FAILED_SCAN_FRAME_BASE));
        reset_test_state();
    }

    #[test]
    fn uninstall_clears_sound_publication_without_primary_context() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let device_key = key(0x0030_0000);
        let owner = owner_key(device_key);
        let _ = sound::unregister_card(owner);
        let _ = sound::ops::clear(owner);

        assert!(sound::reserve_card(owner));
        assert!(sound::ops::register(owner, &SOUND_OPS));
        assert!(sound::register_card(owner));
        assert!(sound::card_number(owner).is_some());
        assert!(sound::ops::ops_for(owner).is_some());

        assert!(uninstall(device_key));
        assert!(sound::card_number(owner).is_none());
        assert!(sound::ops::ops_for(owner).is_none());
        assert!(!uninstall(device_key));
        reset_test_state();
    }

    #[test]
    fn uninstall_removes_only_matching_snd_child_key() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let key0 = key(0x0040_0000);
        let key1 = key(0x0050_0000);
        let owner0 = owner_key(key0);
        let owner1 = owner_key(key1);
        publish_test_card(owner0);
        publish_test_card(owner1);
        {
            let mut ctxs = CTX.lock();
            ctxs.push(ctx(key0));
            ctxs.push(ctx(key1));
        }
        softirq::set_handler(softirq::Slot::SndEvent, test_event_handler);

        assert!(uninstall(key0));
        assert!(!present_for(key0));
        assert!(present_for(key1));
        assert!(sound::card_number(owner0).is_none());
        assert!(sound::ops::ops_for(owner0).is_none());
        assert!(sound::card_number(owner1).is_some());
        assert!(sound::ops::ops_for(owner1).is_some());
        softirq::raise(softirq::Slot::SndEvent);
        // SAFETY: hosted unit test owns the SndEvent slot under TEST_LOCK.
        unsafe { softirq::run_pending(); }
        assert_eq!(TEST_EVENT_CALLS.load(Ordering::Relaxed), 1);

        assert!(uninstall(key1));
        assert!(!present());
        assert!(sound::card_number(owner1).is_none());
        assert!(sound::ops::ops_for(owner1).is_none());
        reset_test_state();
    }

    #[test]
    fn shutdown_removes_only_matching_snd_child_key_without_unpublishing_sound() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let key0 = key(0x0060_0000);
        let key1 = key(0x0070_0000);
        let owner0 = owner_key(key0);
        let owner1 = owner_key(key1);
        publish_test_card(owner0);
        publish_test_card(owner1);
        {
            let mut ctxs = CTX.lock();
            ctxs.push(ctx(key0));
            ctxs.push(ctx(key1));
        }
        softirq::set_handler(softirq::Slot::SndEvent, test_event_handler);

        assert!(shutdown(key0));
        assert!(!present_for(key0));
        assert!(present_for(key1));
        assert!(sound::card_number(owner0).is_some());
        assert!(sound::ops::ops_for(owner0).is_some());
        assert!(sound::card_number(owner1).is_some());
        assert!(sound::ops::ops_for(owner1).is_some());
        softirq::raise(softirq::Slot::SndEvent);
        // SAFETY: hosted unit test owns the SndEvent slot under TEST_LOCK.
        unsafe { softirq::run_pending(); }
        assert_eq!(TEST_EVENT_CALLS.load(Ordering::Relaxed), 1);

        assert!(uninstall(key0));
        assert!(uninstall(key1));
        reset_test_state();
    }
