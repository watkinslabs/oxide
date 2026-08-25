use super::*;

#[test]
fn card_nodes_are_model_owned_and_removed() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(key(0x10));
    let _ = ops::clear(key(0x10));

    assert!(reserve_card(key(0x10)));
    assert!(ops::register(key(0x10), &TEST_OPS));
    assert!(register_card(key(0x10)));
    assert_eq!(owner(), Some(key(0x10)));
    assert_eq!(card_number(key(0x10)), Some(0));
    assert!(register_card(key(0x10)));

    let added = ADDED.lock().clone();
    assert_eq!(added.len(), CARD0_NODE_COUNT);
    assert!(has_node(&added, "snd/controlC0", (116, 0)));
    assert!(has_node(&added, "snd/pcmC0D0p", (116, 16)));
    assert!(has_node(&added, "snd/pcmC0D0c", (116, 24)));
    assert!(drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "controlC0" && d.devname.as_deref() == Some("snd/controlC0")));
    assert!(drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "pcmC0D0p" && d.devname.as_deref() == Some("snd/pcmC0D0p")));
    assert_eq!(REMOVED.lock().len(), 0);
    assert!(has_node(&added, "dsp", (14, 3)));
    assert!(has_node(&added, "dsp0", (14, 3)));
    assert!(has_node(&added, "audio", (14, 4)));
    assert!(has_node(&added, "audio0", (14, 4)));
    assert!(has_node(&added, "mixer", (14, 0)));
    assert!(has_node(&added, "mixer0", (14, 0)));

    assert!(!unregister_card(key(0x20)));
    assert_eq!(REMOVED.lock().len(), 0);
    assert_eq!(owner(), Some(key(0x10)));

    assert!(unregister_card(key(0x10)));
    let removed = REMOVED.lock().clone();
    assert_eq!(removed.len(), CARD0_NODE_COUNT);
    assert!(removed.iter().any(|n| n == "snd/controlC0"));
    assert!(removed.iter().any(|n| n == "snd/pcmC0D0p"));
    assert!(removed.iter().any(|n| n == "snd/pcmC0D0c"));
    assert!(removed.iter().any(|n| n == "dsp"));
    assert!(removed.iter().any(|n| n == "dsp0"));
    assert!(removed.iter().any(|n| n == "audio"));
    assert!(removed.iter().any(|n| n == "audio0"));
    assert!(removed.iter().any(|n| n == "mixer"));
    assert!(removed.iter().any(|n| n == "mixer0"));

    assert!(!unregister_card(key(0x10)));
    assert_eq!(REMOVED.lock().len(), CARD0_NODE_COUNT);
    assert_eq!(owner(), None);
    assert!(ops::ops_for(key(0x10)).is_none());

    ADDED.lock().clear();
    REMOVED.lock().clear();
    assert!(reserve_card(key(0x10)));
    assert!(ops::register(key(0x10), &TEST_OPS));
    assert!(register_card(key(0x10)));
    assert_eq!(ADDED.lock().len(), CARD0_NODE_COUNT);
    assert!(drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "controlC0"));
    assert!(unregister_card(key(0x10)));
    assert_eq!(REMOVED.lock().len(), CARD0_NODE_COUNT);
    let _ = ops::clear(key(0x10));
}

#[test]
fn pcm_devices_are_enumerated_and_published_independently() {
    let _guard = test_guard();
    let owner_id = key(0x7200);
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(owner_id);
    let _ = ops::clear(owner_id);

    assert!(reserve_card(owner_id));
    assert!(ops::register(owner_id, &TEST_OPS));
    assert!(ops::register_pcm_devices(owner_id, &MULTI_DEVICE_OPS));
    assert!(register_card(owner_id));

    let mut next = u32::MAX;
    assert_eq!(crate::control::handle(owner_id, 0, uapi::CTL_PCM_NEXT_DEVICE, &mut next as *mut u32 as u64), 0);
    assert_eq!(next, 0);
    next = 0;
    assert_eq!(crate::control::handle(owner_id, 0, uapi::CTL_PCM_NEXT_DEVICE, &mut next as *mut u32 as u64), 0);
    assert_eq!(next, 1);
    next = 1;
    assert_eq!(crate::control::handle(owner_id, 0, uapi::CTL_PCM_NEXT_DEVICE, &mut next as *mut u32 as u64), 0);
    assert_eq!(next, u32::MAX);

    let mut info = [0u8; uapi::PCM_INFO_SIZE];
    put_u32(&mut info, uapi::PI_DEVICE, 1);
    put_u32(&mut info, uapi::PI_STREAM, uapi::STREAM_PLAYBACK as u32);
    assert_eq!(crate::control::handle(owner_id, 0, uapi::CTL_PCM_INFO, info.as_mut_ptr() as u64), 0);
    assert_eq!(u32::from_le_bytes(info[uapi::PI_DEVICE..uapi::PI_DEVICE + 4].try_into().unwrap()), 1);

    let added = ADDED.lock().clone();
    assert!(has_name(&added, "snd/pcmC0D1p"));
    assert!(has_name(&added, "snd/pcmC0D1c"));

    assert!(unregister_card(owner_id));
    let _ = ops::clear(owner_id);
    let _ = cancel_card_reservation(owner_id);
}

#[test]
fn card_nodes_follow_reported_stream_directions() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);

    for (owner_id, ops_table, expect_playback, expect_capture, expect_count) in [
        (key(0x41), &PLAYBACK_ONLY_OPS, true, false, 8usize),
        (key(0x42), &CAPTURE_ONLY_OPS, false, true, 8usize),
        (key(0x43), &NO_PCM_OPS, false, false, 3usize),
    ] {
        ADDED.lock().clear();
        REMOVED.lock().clear();
        let _ = unregister_card(owner_id);
        let _ = ops::clear(owner_id);

        assert!(reserve_card(owner_id));
        assert!(ops::register(owner_id, ops_table));
        assert!(register_card(owner_id));
        let added = ADDED.lock().clone();
        assert_eq!(added.len(), expect_count);
        assert!(has_node(&added, "snd/controlC0", (116, 0)));
        assert_eq!(has_name(&added, "snd/pcmC0D0p"), expect_playback);
        assert_eq!(has_name(&added, "snd/pcmC0D0c"), expect_capture);
        assert_eq!(has_name(&added, "dsp"), expect_playback || expect_capture);
        assert_eq!(has_name(&added, "audio"), expect_playback || expect_capture);
        assert!(has_node(&added, "mixer", (14, 0)));
        assert_eq!(pcm::has_card(owner_id), expect_playback);
        assert_eq!(capture::has_card(owner_id), expect_capture);
        assert_eq!(oss::has_card(owner_id), expect_playback || expect_capture);

        assert!(unregister_card(owner_id));
        let _ = ops::clear(owner_id);
    }
}

#[test]
fn pcm_control_ops_propagate_backend_failures() {
    let _guard = test_guard();
    let owner_id = key(0x44);
    let _ = pcm::unregister_card(owner_id);
    let _ = capture::unregister_card(owner_id);
    let _ = cancel_card_reservation(owner_id);
    let _ = ops::clear(owner_id);

    assert!(reserve_card(owner_id));
    assert!(ops::register(owner_id, &FAIL_STOP_FREE_OPS));
    pcm::register_card(owner_id);
    capture::register_card(owner_id);

    assert_eq!(pcm::handle(owner_id, 0, 0, uapi::PCM_HW_FREE, 0), test_err(syscall::errno::Errno::Eio));
    assert_eq!(pcm::handle(owner_id, 0, 0, uapi::PCM_DROP, 0), test_err(syscall::errno::Errno::Eio));
    assert_eq!(capture::handle(owner_id, 0, 0, uapi::PCM_HW_FREE, 0), test_err(syscall::errno::Errno::Eio));
    assert_eq!(capture::handle(owner_id, 0, 0, uapi::PCM_DROP, 0), test_err(syscall::errno::Errno::Eio));

    let _ = pcm::unregister_card(owner_id);
    let _ = capture::unregister_card(owner_id);
    let _ = ops::clear(owner_id);
    let _ = cancel_card_reservation(owner_id);
}

#[test]
fn pcm_sync_ptr_does_not_fabricate_hardware_progress() {
    let _guard = test_guard();
    let owner_id = key(0x45);
    let _ = pcm::unregister_card(owner_id);
    let _ = capture::unregister_card(owner_id);
    let _ = cancel_card_reservation(owner_id);
    let _ = ops::clear(owner_id);

    assert!(reserve_card(owner_id));
    assert!(ops::register(owner_id, &TEST_OPS));
    pcm::register_card(owner_id);
    capture::register_card(owner_id);

    let mut sync = [0u8; uapi::SYNC_PTR_SIZE];
    put_u32(&mut sync, uapi::SP_FLAGS, 0);
    put_u64(&mut sync, uapi::SP_CONTROL_APPL_PTR, 77);
    assert_eq!(pcm::handle(owner_id, 0, 0, uapi::PCM_SYNC_PTR, sync.as_mut_ptr() as u64), 0);
    assert_eq!(get_u64(&sync, uapi::SP_CONTROL_APPL_PTR), 77);
    assert_eq!(get_u64(&sync, uapi::SP_STATUS_HW_PTR), 0);

    sync.fill(0);
    put_u32(&mut sync, uapi::SP_FLAGS, 0);
    put_u64(&mut sync, uapi::SP_CONTROL_APPL_PTR, 33);
    assert_eq!(capture::handle(owner_id, 0, 0, uapi::PCM_SYNC_PTR, sync.as_mut_ptr() as u64), 0);
    assert_eq!(get_u64(&sync, uapi::SP_CONTROL_APPL_PTR), 33);
    assert_eq!(get_u64(&sync, uapi::SP_STATUS_HW_PTR), 0);

    // A card that does not advertise SNDRV_PCM_INFO_PAUSE refuses PAUSE
    // before any state check, the way ALSA's pre-action does.
    assert_eq!(pcm::handle(owner_id, 0, 0, uapi::PCM_PAUSE, 0), test_err(syscall::errno::Errno::Enosys));
    let _ = pcm::unregister_card(owner_id);
    let _ = capture::unregister_card(owner_id);
    let _ = ops::clear(owner_id);
    let _ = cancel_card_reservation(owner_id);
}

#[test]
fn card_reservation_allocates_per_owner_cards_before_publication() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(key(0x10));
    let _ = unregister_card(key(0x20));
    let _ = ops::clear(key(0x10));
    let _ = ops::clear(key(0x20));

    assert!(reserve_card(key(0x10)));
    assert_eq!(owner(), Some(key(0x10)));
    assert_eq!(card_number(key(0x10)), Some(0));
    assert!(reserve_card(key(0x10)));
    assert!(reserve_card(key(0x20)));
    assert_eq!(card_number(key(0x20)), Some(1));
    assert_eq!(ADDED.lock().len(), 0);

    assert!(ops::register(key(0x10), &TEST_OPS));
    assert!(ops::register(key(0x20), &TEST_OPS));
    assert!(register_card(key(0x10)));
    assert!(register_card(key(0x20)));

    let added = ADDED.lock().clone();
    assert_eq!(added.len(), CARD0_NODE_COUNT + CARD1_NODE_COUNT);
    assert!(has_node(&added, "snd/controlC0", (116, 0)));
    assert!(has_node(&added, "snd/pcmC0D0p", (116, 16)));
    assert!(has_node(&added, "snd/pcmC0D0c", (116, 24)));
    assert!(has_node(&added, "snd/controlC1", (116, 32)));
    assert!(has_node(&added, "snd/pcmC1D0p", (116, 48)));
    assert!(has_node(&added, "snd/pcmC1D0c", (116, 56)));
    assert!(has_node(&added, "dsp1", (14, 19)));
    assert!(has_node(&added, "audio1", (14, 20)));
    assert!(has_node(&added, "mixer1", (14, 16)));

    assert!(unregister_card(key(0x10)));
    assert_eq!(owner(), Some(key(0x20)));
    assert_eq!(card_number(key(0x20)), Some(1));
    assert!(ops::ops_for(key(0x10)).is_none());
    assert!(ops::ops_for(key(0x20)).is_some());
    assert!(unregister_card(key(0x20)));
    assert_eq!(owner(), None);
    assert!(ops::ops_for(key(0x10)).is_none());
    assert!(ops::ops_for(key(0x20)).is_none());
}

#[test]
fn sound_data_paths_route_ops_by_explicit_owner() {
    let _guard = test_guard();
    let owner0 = key(0x7100);
    let owner1 = key(0x7101);
    for owner_id in [owner0, owner1] {
        let _ = unregister_card(owner_id);
        let _ = ops::clear(owner_id);
        assert!(reserve_card(owner_id));
        assert!(ops::register(owner_id, &ROUTE_OPS));
        pcm::register_card(owner_id);
        capture::register_card(owner_id);
        oss::register_card(owner_id);
    }
    ROUTED.lock().clear();

    assert_eq!(pcm::handle(owner1, 1, 0, uapi::PCM_PREPARE, 0), 0);
    assert_eq!(pcm::write_bytes(owner1, 0, &[1, 2, 3, 4]), 4);
    assert_eq!(capture::handle(owner1, 1, 0, uapi::PCM_PREPARE, 0), 0);
    let mut input = [0u8; 4];
    assert_eq!(capture::read_bytes(owner1, 0, &mut input), 4);
    assert_eq!(oss::write(owner1, &[5, 6, 7, 8]), 4);
    let mut next = [0u8; 4];
    assert_eq!(crate::control::handle(owner1, 1, uapi::CTL_PCM_NEXT_DEVICE, next.as_mut_ptr() as u64), 0);

    let routed = ROUTED.lock().clone();
    assert!(!routed.is_empty());
    assert!(routed.iter().all(|owner_id| *owner_id == owner1));

    for owner_id in [owner0, owner1] {
        pcm::unregister_card(owner_id);
        capture::unregister_card(owner_id);
        oss::unregister_card(owner_id);
        let _ = ops::clear(owner_id);
        let _ = cancel_card_reservation(owner_id);
    }
}

#[test]
fn cancel_card_reservation_only_releases_unpublished_cards() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(key(0x10));
    let _ = unregister_card(key(0x20));
    let _ = ops::clear(key(0x10));
    let _ = ops::clear(key(0x20));

    assert!(reserve_card(key(0x10)));
    assert!(cancel_card_reservation(key(0x10)));
    assert_eq!(card_number(key(0x10)), None);
    assert!(!cancel_card_reservation(key(0x10)));
    assert_eq!(ADDED.lock().len(), 0);
    assert_eq!(REMOVED.lock().len(), 0);

    assert!(reserve_card(key(0x20)));
    assert!(ops::register(key(0x20), &TEST_OPS));
    assert!(register_card(key(0x20)));
    assert!(!cancel_card_reservation(key(0x20)));
    assert_eq!(card_number(key(0x20)), Some(0));
    assert!(unregister_card(key(0x20)));
    assert!(ops::ops_for(key(0x20)).is_none());
    let _ = ops::clear(key(0x20));
}

#[test]
fn card_publication_conflict_rolls_back_partial_nodes_and_owner_state() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(key(0x10));
    let _ = unregister_card(key(0x20));
    let _ = unregister_card(key(0x30));
    let _ = ops::clear(key(0x10));
    let _ = ops::clear(key(0x20));
    let _ = ops::clear(key(0x30));

    let conflict = drv::try_device_add(Arc::new(
        drv::Device::new("sound", String::from("pcmC0D0p"), 0, 0, crate::device::MINOR_PCM_P as u32)
            .with_devnode("sound", String::from("snd/pcmC0D0p"), Some((116, 16)))))
        .expect("conflict device registration");
    ADDED.lock().clear();
    REMOVED.lock().clear();

    assert!(reserve_card(key(0x30)));
    assert!(ops::register(key(0x30), &TEST_OPS));
    assert!(!register_card(key(0x30)));

    let added = ADDED.lock().clone();
    assert_eq!(added.len(), 1);
    assert!(has_node(&added, "snd/controlC0", (116, 0)));
    let removed = REMOVED.lock().clone();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0], String::from("snd/controlC0"));
    assert!(!drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "controlC0"));
    assert!(drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "pcmC0D0p"));
    assert_eq!(owner(), None);
    assert_eq!(card_number(key(0x30)), None);
    assert!(ops::ops_for(key(0x30)).is_none());
    assert!(!pcm::has_card(key(0x30)));
    assert!(!capture::has_card(key(0x30)));
    assert!(!oss::has_card(key(0x30)));

    drv::device_del(&conflict);
    let _ = ops::clear(key(0x30));
}

#[test]
fn substream_runtime_state_is_owner_keyed() {
    let _guard = test_guard();

    pcm::unregister_card(key(0x10));
    pcm::unregister_card(key(0x20));
    capture::unregister_card(key(0x10));
    capture::unregister_card(key(0x20));
    oss::unregister_card(key(0x10));
    oss::unregister_card(key(0x20));

    pcm::register_card(key(0x10));
    pcm::register_card(key(0x20));
    pcm::register_card(key(0x10));
    capture::register_card(key(0x10));
    capture::register_card(key(0x20));
    capture::register_card(key(0x10));
    oss::register_card(key(0x10));
    oss::register_card(key(0x20));
    oss::register_card(key(0x10));

    assert_eq!(pcm::registered_count(), 2);
    assert!(pcm::has_card(key(0x10)));
    assert!(pcm::has_card(key(0x20)));
    assert_eq!(capture::registered_count(), 2);
    assert!(capture::has_card(key(0x10)));
    assert!(capture::has_card(key(0x20)));
    assert_eq!(oss::registered_count(), 2);
    assert!(oss::has_card(key(0x10)));
    assert!(oss::has_card(key(0x20)));

    pcm::unregister_card(key(0x10));
    capture::unregister_card(key(0x10));
    oss::unregister_card(key(0x10));

    assert_eq!(pcm::registered_count(), 1);
    assert!(!pcm::has_card(key(0x10)));
    assert!(pcm::has_card(key(0x20)));
    assert_eq!(capture::registered_count(), 1);
    assert!(!capture::has_card(key(0x10)));
    assert!(capture::has_card(key(0x20)));
    assert_eq!(oss::registered_count(), 1);
    assert!(!oss::has_card(key(0x10)));
    assert!(oss::has_card(key(0x20)));

    pcm::unregister_card(key(0x20));
    capture::unregister_card(key(0x20));
    oss::unregister_card(key(0x20));
}
