use super::*;

fn install(owner: crate::SoundOwnerKey) {
    let _ = pcm::unregister_card(owner);
    let _ = capture::unregister_card(owner);
    let _ = cancel_card_reservation(owner);
    let _ = ops::clear(owner);
    assert!(reserve_card(owner));
    assert!(ops::register(owner, &TEST_OPS));
    pcm::register_card(owner);
    capture::register_card(owner);
}
fn remove(owner: crate::SoundOwnerKey) {
    pcm::unregister_card(owner);
    capture::unregister_card(owner);
    let _ = ops::clear(owner);
    let _ = cancel_card_reservation(owner);
}

#[test]
fn timestamp_type_selects_the_status_clock_for_playback_and_capture() {
    let _guard = test_guard();
    let owner = key(0x46);
    install(owner);

    let mut invalid = uapi::TSTAMP_TYPE_MONOTONIC_RAW + 1;
    assert_eq!(pcm::handle(owner, 0, 0, uapi::PCM_TSTAMP, (&mut invalid as *mut u32) as u64),
        test_err(syscall::errno::Errno::Einval));
    assert_eq!(capture::handle(owner, 0, 0, uapi::PCM_TTSTAMP, 0),
        test_err(syscall::errno::Errno::Efault));

    let mut sw = [0u8; uapi::SW_PARAMS_SIZE];
    put_u32(&mut sw, uapi::SWP_TSTAMP_MODE, uapi::TSTAMP_ENABLE);
    put_u32(&mut sw, uapi::SWP_PROTO, uapi::PCM_PROTO_TSTAMP_TYPE);
    put_u32(&mut sw, uapi::SWP_TSTAMP_TYPE, uapi::TSTAMP_TYPE_MONOTONIC);
    assert_eq!(pcm::handle(owner, 0, 0, uapi::PCM_SW_PARAMS, sw.as_mut_ptr() as u64), 0);
    assert_eq!(capture::handle(owner, 0, 0, uapi::PCM_SW_PARAMS, sw.as_mut_ptr() as u64), 0);

    let mut playback_kind = uapi::TSTAMP_TYPE_MONOTONIC_RAW;
    let mut capture_kind = uapi::TSTAMP_TYPE_REALTIME;
    assert_eq!(pcm::handle(owner, 0, 0, uapi::PCM_TSTAMP,
                          (&mut playback_kind as *mut u32) as u64), 0);
    assert_eq!(capture::handle(owner, 0, 0, uapi::PCM_TTSTAMP,
                              (&mut capture_kind as *mut u32) as u64), 0);

    crate::pcm_time::set_test_clock(uapi::TSTAMP_TYPE_REALTIME, 11_250_000_001);
    crate::pcm_time::set_test_clock(uapi::TSTAMP_TYPE_MONOTONIC_RAW, 33_750_000_002);
    let mut open_status = [0u8; uapi::STATUS_SIZE];
    assert_eq!(pcm::handle(owner, 0, 0, uapi::PCM_STATUS, open_status.as_mut_ptr() as u64), 0);
    assert_eq!(get_u64(&open_status, uapi::ST_TSTAMP_SEC), 0);
    assert_eq!(pcm::handle(owner, 0, 0, uapi::PCM_PREPARE, 0), 0);
    assert_eq!(capture::handle(owner, 0, 0, uapi::PCM_PREPARE, 0), 0);
    assert_eq!(pcm::handle(owner, 0, 0, uapi::PCM_START, 0), 0);
    assert_eq!(capture::handle(owner, 0, 0, uapi::PCM_START, 0), 0);

    crate::pcm_time::set_test_clock(uapi::TSTAMP_TYPE_REALTIME, 12_500_000_003);
    crate::pcm_time::set_test_clock(uapi::TSTAMP_TYPE_MONOTONIC_RAW, 34_125_000_004);
    let mut playback = [0u8; uapi::STATUS_SIZE];
    let mut captured = [0u8; uapi::STATUS_SIZE];
    assert_eq!(pcm::handle(owner, 0, 0, uapi::PCM_STATUS, playback.as_mut_ptr() as u64), 0);
    assert_eq!(capture::handle(owner, 0, 0, uapi::PCM_STATUS, captured.as_mut_ptr() as u64), 0);

    assert_eq!(get_u64(&playback, uapi::ST_TRIGGER_SEC), 33);
    assert_eq!(get_u64(&playback, uapi::ST_TRIGGER_NSEC), 750_000_002);
    assert_eq!(get_u64(&playback, uapi::ST_TSTAMP_SEC), 34);
    assert_eq!(get_u64(&playback, uapi::ST_TSTAMP_NSEC), 125_000_004);
    assert_eq!(get_u64(&captured, uapi::ST_TRIGGER_SEC), 11);
    assert_eq!(get_u64(&captured, uapi::ST_TRIGGER_NSEC), 250_000_001);
    assert_eq!(get_u64(&captured, uapi::ST_TSTAMP_SEC), 12);
    assert_eq!(get_u64(&captured, uapi::ST_TSTAMP_NSEC), 500_000_003);

    let mut sync = [0u8; uapi::SYNC_PTR_SIZE];
    assert_eq!(pcm::handle(owner, 0, 0, uapi::PCM_SYNC_PTR, sync.as_mut_ptr() as u64), 0);
    assert_eq!(get_u64(&sync, uapi::SP_STATUS_TSTAMP_SEC), 34);
    assert_eq!(get_u64(&sync, uapi::SP_STATUS_TSTAMP_NSEC), 125_000_004);

    remove(owner);
}
