// Provenance: the SNDRV_CTL_IOCTL_* contract `alsactl`/`alsamixer` depend on
// — card identity strings coming from the card, PCM device enumeration, and
// element list/info/read/write/TLV over driver-registered controls.

use super::*;
use crate::elem::{DbScale, ElemDesc, ElemOps, ElemValues, ENUM_NAME_WIDTH, MAX_ELEM_CHANNELS};
use crate::ops;

static LEVEL: sync::Spinlock<[i64; MAX_ELEM_CHANNELS], sync::TaskList> =
    sync::Spinlock::new([0; MAX_ELEM_CHANNELS]);

fn ident(_owner: crate::SoundOwnerKey) -> crate::CardIdentity {
    crate::CardIdentity::new(b"HDA", b"HDA Intel", b"HDA Card", b"HDA Card at 0xf0000000",
                             b"Test Mixer", b"HDA:0001", b"HDA Analog")
}
fn cfg(_owner: crate::SoundOwnerKey) -> Option<(u32, u32, u32, u32)> { Some((0, 0, 0, 0)) }
fn caps(_owner: crate::SoundOwnerKey) -> ops::Caps { Some((1u64 << FMT_S16_LE, 1u64 << 6, 1, 2)) }
fn limits(_owner: crate::SoundOwnerKey) -> ops::HwLimits { (4096, 16384) }
fn info_flags(_owner: crate::SoundOwnerKey) -> u32 { crate::uapi::PCM_INFO_PAUSE }
fn period(_owner: crate::SoundOwnerKey) -> usize { 2048 }
fn hw_params(_owner: crate::SoundOwnerKey, _format: u32, _rate_hz: u32, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool { true }
fn yes(_owner: crate::SoundOwnerKey) -> bool { true }
fn pause(_owner: crate::SoundOwnerKey, _pause: bool) -> bool { true }
fn no_pointer(_owner: crate::SoundOwnerKey) -> Option<u64> { None }
fn trigger(_owner: crate::SoundOwnerKey, _start: bool) -> bool { true }
fn submit(_owner: crate::SoundOwnerKey, b: &[u8]) -> usize { b.len() }
fn recv(_owner: crate::SoundOwnerKey, b: &mut [u8]) -> usize { b.len() }

static TEST_OPS: ops::SoundOps = ops::SoundOps {
    identity: ident, config: cfg, pcm_caps: caps, cap_caps: caps, hw_limits: limits, info_flags: info_flags, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_pause: pause, pcm_drain: yes,
    pcm_pointer: no_pointer, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_pointer: no_pointer,
    cap_hw_free: yes, pcm_recv: recv,
};

fn elem_get(_owner: crate::SoundOwnerKey, _private: u32, out: &mut ElemValues) -> bool {
    *out = *LEVEL.lock();
    true
}
fn elem_put(_owner: crate::SoundOwnerKey, _private: u32, values: &ElemValues) -> bool {
    *LEVEL.lock() = *values;
    true
}
fn elem_enum(_owner: crate::SoundOwnerKey, _private: u32, item: u32, out: &mut [u8; ENUM_NAME_WIDTH]) -> bool {
    let names: [&[u8]; 2] = [b"Mic", b"Line"];
    let Some(name) = names.get(item as usize) else { return false; };
    out[..name.len()].copy_from_slice(name);
    true
}
static ELEM_OPS: ElemOps = ElemOps { get: elem_get, put: elem_put, enum_name: elem_enum };

const MASTER_MAX: i64 = 87;

fn master() -> ElemDesc {
    ElemDesc {
        id: crate::elem::ElemId::mixer(b"Master Playback Volume", 0),
        etype: CTL_ELEM_TYPE_INTEGER,
        access: CTL_ELEM_ACCESS_READWRITE | CTL_ELEM_ACCESS_TLV_READ,
        count: 2, min: 0, max: MASTER_MAX, step: 0, items: 0,
        tlv: Some(DbScale { min_centibel: -6525, step_centibel: 75, mute: true }),
        private: 1, ops: &ELEM_OPS,
    }
}

fn u32_at(buf: &[u8], off: usize) -> u32 { u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) }
fn u64_at(buf: &[u8], off: usize) -> u64 { u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) }
fn put_u32(buf: &mut [u8], off: usize, value: u32) { buf[off..off + 4].copy_from_slice(&value.to_le_bytes()); }
fn put_u64(buf: &mut [u8], off: usize, value: u64) { buf[off..off + 8].copy_from_slice(&value.to_le_bytes()); }
fn put_id(buf: &mut [u8], numid: u32) {
    put_u32(buf, CEI_NUMID, numid);
    put_u32(buf, CEI_IFACE, CTL_ELEM_IFACE_MIXER);
}
fn key(raw: u32) -> crate::SoundOwnerKey { crate::SoundOwnerKey::from_raw(raw).unwrap() }

fn arm(raw: u32) -> crate::SoundOwnerKey {
    let owner = key(raw);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);
    crate::elem::unregister_card(owner);
    assert!(crate::reserve_card(owner));
    assert!(crate::ops::register(owner, &TEST_OPS));
    owner
}

fn disarm(owner: crate::SoundOwnerKey) {
    crate::elem::unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);
}

#[test]
fn card_info_reports_the_driver_identity_not_a_hard_coded_name() {
    let _guard = crate::tests::test_guard();
    let owner = arm(0x5110);
    let mut info = [0u8; CARD_INFO_SIZE];
    assert_eq!(handle(owner, 4, CTL_CARD_INFO, info.as_mut_ptr() as u64), 0);
    assert_eq!(u32_at(&info, CI_CARD), 4);
    assert_eq!(crate::identity::trim(&info[CI_ID..CI_ID + 16]), b"HDA");
    assert_eq!(crate::identity::trim(&info[CI_DRIVER..CI_DRIVER + 16]), b"HDA Intel");
    assert_eq!(crate::identity::trim(&info[CI_NAME..CI_NAME + 32]), b"HDA Card");
    assert_eq!(crate::identity::trim(&info[CI_LONGNAME..CI_LONGNAME + 80]), b"HDA Card at 0xf0000000");
    assert_eq!(crate::identity::trim(&info[CI_COMPONENTS..CI_COMPONENTS + 128]), b"HDA:0001");
    disarm(owner);
}

#[test]
fn control_pcm_info_reports_playback_and_capture_streams() {
    let _guard = crate::tests::test_guard();
    let owner = arm(0x5102);
    let mut info = [0u8; PCM_INFO_SIZE];
    put_u32(&mut info, PI_DEVICE, 0);
    put_u32(&mut info, PI_STREAM, STREAM_PLAYBACK as u32);
    assert_eq!(handle(owner, 3, CTL_PCM_INFO, info.as_mut_ptr() as u64), 0);
    assert_eq!(u32_at(&info, PI_STREAM), STREAM_PLAYBACK as u32);
    assert_eq!(u32_at(&info, PI_CARD), 3);
    assert_eq!(crate::identity::trim(&info[PI_NAME..PI_NAME + 80]), b"HDA Analog Playback");

    info.fill(0);
    put_u32(&mut info, PI_STREAM, STREAM_CAPTURE as u32);
    assert_eq!(handle(owner, 3, CTL_PCM_INFO, info.as_mut_ptr() as u64), 0);
    assert_eq!(crate::identity::trim(&info[PI_NAME..PI_NAME + 80]), b"HDA Analog Capture");

    info.fill(0);
    put_u32(&mut info, PI_STREAM, 99);
    assert_eq!(handle(owner, 3, CTL_PCM_INFO, info.as_mut_ptr() as u64),
               -(Errno::Enoent.as_i32() as i64));
    disarm(owner);
}

#[test]
fn a_card_with_no_registered_controls_exposes_no_elements() {
    let _guard = crate::tests::test_guard();
    let owner = arm(0x5100);
    let mut ids = [0u8; CTL_ELEM_ID_SIZE * 2];
    let mut list = [0u8; CTL_ELEM_LIST_SIZE];
    put_u32(&mut list, CEL_SPACE, 2);
    put_u64(&mut list, CEL_PIDS, ids.as_mut_ptr() as u64);
    assert_eq!(handle(owner, 0, CTL_ELEM_LIST, list.as_mut_ptr() as u64), 0);
    assert_eq!(u32_at(&list, CEL_USED), 0);
    assert_eq!(u32_at(&list, CEL_COUNT), 0);
    assert_eq!(ids, [0u8; CTL_ELEM_ID_SIZE * 2]);

    let mut info = [0u8; CTL_ELEM_INFO_SIZE];
    put_id(&mut info, 1);
    assert_eq!(handle(owner, 0, CTL_ELEM_INFO, info.as_mut_ptr() as u64),
               -(Errno::Enoent.as_i32() as i64));
    assert_eq!(mixer_level(owner), None);
    assert!(!set_mixer_level(owner, 80 | (90 << 8)));
    disarm(owner);
}

#[test]
fn registered_elements_are_listed_described_read_and_written() {
    let _guard = crate::tests::test_guard();
    let owner = arm(0x5111);
    let numid = crate::elem::register(owner, master());
    *LEVEL.lock() = [0; MAX_ELEM_CHANNELS];

    let mut ids = [0u8; CTL_ELEM_ID_SIZE * 4];
    let mut list = [0u8; CTL_ELEM_LIST_SIZE];
    put_u32(&mut list, CEL_SPACE, 4);
    put_u64(&mut list, CEL_PIDS, ids.as_mut_ptr() as u64);
    assert_eq!(handle(owner, 0, CTL_ELEM_LIST, list.as_mut_ptr() as u64), 0);
    assert_eq!(u32_at(&list, CEL_COUNT), 1);
    assert_eq!(u32_at(&list, CEL_USED), 1);
    assert_eq!(u32_at(&ids, CEI_NUMID), numid);
    assert_eq!(u32_at(&ids, CEI_IFACE), CTL_ELEM_IFACE_MIXER);
    assert_eq!(crate::identity::trim(&ids[CEI_NAME..CEI_NAME + CEI_NAME_LEN]), b"Master Playback Volume");

    let mut info = [0u8; CTL_ELEM_INFO_SIZE];
    put_id(&mut info, numid);
    assert_eq!(handle(owner, 0, CTL_ELEM_INFO, info.as_mut_ptr() as u64), 0);
    assert_eq!(u32_at(&info, CEINFO_TYPE), CTL_ELEM_TYPE_INTEGER);
    assert_eq!(u32_at(&info, CEINFO_COUNT), 2);
    assert_eq!(u64_at(&info, CEINFO_INTEGER_MIN), 0);
    assert_eq!(u64_at(&info, CEINFO_INTEGER_MAX), MASTER_MAX as u64);

    let mut value = [0u8; CTL_ELEM_VALUE_SIZE];
    put_id(&mut value, numid);
    put_u64(&mut value, CEV_VALUE, 40);
    put_u64(&mut value, CEV_VALUE + 8, 41);
    // First write changes the value, a repeat of the same value does not.
    assert_eq!(handle(owner, 0, CTL_ELEM_WRITE, value.as_mut_ptr() as u64), 1);
    assert_eq!(handle(owner, 0, CTL_ELEM_WRITE, value.as_mut_ptr() as u64), 0);

    value.fill(0);
    put_id(&mut value, numid);
    assert_eq!(handle(owner, 0, CTL_ELEM_READ, value.as_mut_ptr() as u64), 0);
    assert_eq!(u64_at(&value, CEV_VALUE), 40);
    assert_eq!(u64_at(&value, CEV_VALUE + 8), 41);
    disarm(owner);
}

#[test]
fn an_out_of_range_element_write_is_einval_and_does_not_reach_the_driver() {
    let _guard = crate::tests::test_guard();
    let owner = arm(0x5112);
    let numid = crate::elem::register(owner, master());
    *LEVEL.lock() = [7; MAX_ELEM_CHANNELS];
    let mut value = [0u8; CTL_ELEM_VALUE_SIZE];
    put_id(&mut value, numid);
    put_u64(&mut value, CEV_VALUE, (MASTER_MAX + 1) as u64);
    assert_eq!(handle(owner, 0, CTL_ELEM_WRITE, value.as_mut_ptr() as u64),
               -(Errno::Einval.as_i32() as i64));
    assert_eq!(LEVEL.lock()[0], 7);
    disarm(owner);
}

#[test]
fn tlv_read_returns_the_db_scale_and_refuses_a_short_buffer() {
    let _guard = crate::tests::test_guard();
    let owner = arm(0x5113);
    let numid = crate::elem::register(owner, master());
    let mut tlv = [0u8; CTL_TLV_HEADER_SIZE + 16];
    put_u32(&mut tlv, CTL_TLV_NUMID, numid);
    put_u32(&mut tlv, CTL_TLV_LENGTH, 16);
    assert_eq!(handle(owner, 0, CTL_TLV_READ, tlv.as_mut_ptr() as u64), 0);
    assert_eq!(u32_at(&tlv, CTL_TLV_DATA), CTL_TLVT_DB_SCALE);
    assert_eq!(u32_at(&tlv, CTL_TLV_DATA + 4), 8);
    assert_eq!(u32_at(&tlv, CTL_TLV_DATA + 8) as i32, -6525);
    assert_eq!(u32_at(&tlv, CTL_TLV_DATA + 12), 75 | CTL_TLV_DB_SCALE_MUTE);

    put_u32(&mut tlv, CTL_TLV_LENGTH, 4);
    assert_eq!(handle(owner, 0, CTL_TLV_READ, tlv.as_mut_ptr() as u64),
               -(Errno::Enomem.as_i32() as i64));
    disarm(owner);
}

#[test]
fn the_oss_mixer_bridge_scales_the_master_element_onto_percent() {
    let _guard = crate::tests::test_guard();
    let owner = arm(0x5114);
    crate::elem::register(owner, master());
    *LEVEL.lock() = [0; MAX_ELEM_CHANNELS];
    assert_eq!(mixer_level(owner), Some(0));

    assert!(set_mixer_level(owner, 100 | (50 << 8)));
    let values = *LEVEL.lock();
    assert_eq!(values[0], MASTER_MAX);
    assert_eq!(values[1], (MASTER_MAX + 1) / 2);
    let packed = mixer_level(owner).unwrap();
    assert_eq!(packed & 0xFF, 100);
    assert!((packed >> 8).abs_diff(50) <= 1);

    let read_req = (2u64 << 30) | (4u64 << 16) | ((b'M' as u64) << 8);
    let mut level = 0u32;
    assert_eq!(crate::oss::handle(owner, true, read_req, (&mut level as *mut u32) as u64), 0);
    assert_eq!(level & 0xFF, 100);
    disarm(owner);
}

#[test]
fn an_element_write_queues_a_value_event_for_subscribers() {
    let _guard = crate::tests::test_guard();
    let owner = arm(0x5115);
    events::unregister_card(owner);
    let numid = crate::elem::register(owner, master());
    *LEVEL.lock() = [0; MAX_ELEM_CHANNELS];
    let cursor = events::latest_seq(owner);

    let mut value = [0u8; CTL_ELEM_VALUE_SIZE];
    put_id(&mut value, numid);
    put_u64(&mut value, CEV_VALUE, 12);
    put_u64(&mut value, CEV_VALUE + 8, 12);
    assert_eq!(handle(owner, 0, CTL_ELEM_WRITE, value.as_mut_ptr() as u64), 1);

    let mut event = [0u8; CTL_EVENT_SIZE];
    let seq = crate::control::read_event(owner, cursor, &mut event).unwrap();
    assert_eq!(u32_at(&event, 0), CTL_EVENT_ELEM);
    assert_eq!(u32_at(&event, CTL_EVENT_MASK), CTL_EVENT_MASK_VALUE);
    assert_eq!(u32_at(&event, CTL_EVENT_ID + CEI_NUMID), numid);
    assert_eq!(crate::identity::trim(&event[CTL_EVENT_ID + CEI_NAME..CTL_EVENT_ID + CEI_NAME + CEI_NAME_LEN]),
               b"Master Playback Volume");
    assert!(crate::control::read_event(owner, seq, &mut event).is_none());
    disarm(owner);
    events::unregister_card(owner);
}
