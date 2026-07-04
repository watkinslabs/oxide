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

