use super::*;
    use core::sync::atomic::AtomicU64;

    static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());
    static TEST_EVENT_CALLS: AtomicU64 = AtomicU64::new(0);

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

    fn reset_test_state() {
        CTX.lock().clear();
        TEST_EVENT_CALLS.store(0, Ordering::Relaxed);
        DRAINED_EVENTS.store(0, Ordering::Relaxed);
        LAST_EVENT.store(0, Ordering::Relaxed);
        let _ = softirq::clear_handler(softirq::Slot::SndEvent);
    }

    fn publish_test_card(owner: u32) {
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
    fn eventq_drain_accounting_is_keyed_by_snd_context() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        const USED_BYTES: usize = 4 + 8 * 8;
        const AVAIL_BYTES: usize = 4 + 8 * 2;
        let mut used0 = [0u8; USED_BYTES];
        let mut avail0 = [0u8; AVAIL_BYTES];
        let mut events0 = [0u8; 8 * EVENT_SIZE];
        let mut notify0 = 0u16;
        let mut used1 = [0u8; USED_BYTES];
        let mut avail1 = [0u8; AVAIL_BYTES];
        let mut events1 = [0u8; 8 * EVENT_SIZE];
        let mut notify1 = 0u16;
        put_u16(&mut used1, 2, 2);
        put_u32(&mut used1, 4, 3);
        put_u32(&mut used1, 12, 4);
        put_event(&mut events1, 3, 0xcccc_0000_0000_0003);
        put_event(&mut events1, 4, 0xcccc_0000_0000_0004);

        let mut c0 = ctx(key(0x0010_0000));
        let mut q0 = queue(1);
        q0.device_pa = used0.as_mut_ptr() as u64;
        q0.driver_pa = avail0.as_mut_ptr() as u64;
        q0.notify_va = (&mut notify0 as *mut u16) as u64;
        c0.eventq = Some(q0);
        c0.event_buf_pa = events0.as_mut_ptr() as u64;
        let mut c1 = ctx(key(0x0020_0000));
        let mut q1 = queue(1);
        q1.device_pa = used1.as_mut_ptr() as u64;
        q1.driver_pa = avail1.as_mut_ptr() as u64;
        q1.notify_va = (&mut notify1 as *mut u16) as u64;
        c1.eventq = Some(q1);
        c1.event_buf_pa = events1.as_mut_ptr() as u64;
        CTX.lock().extend([c0, c1]);

        event_softirq();

        assert_eq!(event_stats_for(key(0x0010_0000)), Some((0, 0)));
        assert_eq!(event_stats_for(key(0x0020_0000)), Some((2, 0xcccc_0000_0000_0004)));
        assert_eq!(eventq_state_for(key(0x0010_0000)), Some((8, 0, 0)));
        assert_eq!(eventq_state_for(key(0x0020_0000)), Some((8, 2, 2)));
        assert_eq!(get_u16(&avail0, 2), 0);
        assert_eq!(get_u16(&avail1, 2), 2);
        assert_eq!(get_u16(&avail1, 4), 3);
        assert_eq!(get_u16(&avail1, 6), 4);
        assert_eq!(notify0, 0);
        assert_eq!(notify1, 1);
        assert_eq!(DRAINED_EVENTS.load(Ordering::Relaxed), 2);
        assert_eq!(LAST_EVENT.load(Ordering::Relaxed), 0xcccc_0000_0000_0004);
        reset_test_state();
    }

    #[test]
    fn caps_exist_only_for_scanned_stream_directions() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let owner = sound_owner(key(0x0010_0000));
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
    fn uninstall_clears_sound_publication_without_primary_context() {
        let _guard = TEST_LOCK.lock();
        reset_test_state();
        let device_key = key(0x0030_0000);
        let owner = sound_owner(device_key);
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
        let owner0 = sound_owner(key0);
        let owner1 = sound_owner(key1);
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
        let owner0 = sound_owner(key0);
        let owner1 = sound_owner(key1);
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
