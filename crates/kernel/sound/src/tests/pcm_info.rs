use super::*;

fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

#[test]
fn direct_pcm_info_reports_node_card_number() {
    let _guard = test_guard();
    let owner0 = key(0x46);
    let owner1 = key(0x47);
    for owner_id in [owner0, owner1] {
        let _ = pcm::unregister_card(owner_id);
        let _ = capture::unregister_card(owner_id);
        let _ = cancel_card_reservation(owner_id);
        let _ = ops::clear(owner_id);
    }

    assert!(reserve_card(owner0));
    assert!(reserve_card(owner1));
    assert_eq!(card_number(owner1), Some(1));
    assert!(ops::register(owner1, &TEST_OPS));
    pcm::register_card(owner1);
    capture::register_card(owner1);

    let mut info = [0u8; uapi::PCM_INFO_SIZE];
    assert_eq!(pcm::handle(owner1, 1, uapi::PCM_INFO, info.as_mut_ptr() as u64), 0);
    assert_eq!(get_u32(&info, uapi::PI_DEVICE), 0);
    assert_eq!(get_u32(&info, uapi::PI_SUBDEVICE), 0);
    assert_eq!(get_u32(&info, uapi::PI_STREAM), uapi::STREAM_PLAYBACK as u32);
    assert_eq!(get_u32(&info, uapi::PI_CARD), 1);

    info.fill(0);
    assert_eq!(capture::handle(owner1, 1, uapi::PCM_INFO, info.as_mut_ptr() as u64), 0);
    assert_eq!(get_u32(&info, uapi::PI_DEVICE), 0);
    assert_eq!(get_u32(&info, uapi::PI_SUBDEVICE), 0);
    assert_eq!(get_u32(&info, uapi::PI_STREAM), uapi::STREAM_CAPTURE as u32);
    assert_eq!(get_u32(&info, uapi::PI_CARD), 1);

    let _ = pcm::unregister_card(owner1);
    let _ = capture::unregister_card(owner1);
    let _ = ops::clear(owner1);
    let _ = cancel_card_reservation(owner1);
    let _ = cancel_card_reservation(owner0);
}
