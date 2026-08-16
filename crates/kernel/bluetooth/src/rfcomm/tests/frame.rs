//! Framing contract: field packing round-trips for every channel and direction,
//! the length field widens, and a bad check byte is refused.

use crate::rfcomm::frame::{self, FrameError, FRAME_MIN_LEN};
use crate::uapi::rfcomm as u;

#[test]
fn address_control_and_dlci_round_trip_for_every_channel_and_direction() {
    for channel in u::RFCOMM_CHANNEL_MIN..=u::RFCOMM_CHANNEL_MAX {
        for initiator in [true, false] {
            let dir = u::session_dir(initiator);
            let dlci = u::dlci(dir, channel);
            assert_eq!(u::srv_channel(dlci), channel);
            assert_eq!(dlci & 0x01, dir);
            for cr in [true, false] {
                let a = u::addr(cr, dlci);
                assert!(u::test_ea(a));
                assert_eq!(u::test_cr(a), cr);
                assert_eq!(u::get_dlci(a), dlci);
            }
            for ftype in [u::RFCOMM_SABM, u::RFCOMM_DISC, u::RFCOMM_UA, u::RFCOMM_DM, u::RFCOMM_UIH] {
                for pf in [true, false] {
                    let c = u::ctrl(ftype, pf);
                    assert_eq!(u::get_type(c), ftype);
                    assert_eq!(u::test_pf(c), pf);
                }
            }
        }
    }
}

#[test]
fn the_two_directions_of_a_channel_are_different_dlcis() {
    for channel in u::RFCOMM_CHANNEL_MIN..=u::RFCOMM_CHANNEL_MAX {
        assert_ne!(u::dlci(u::session_dir(true), channel), u::dlci(u::session_dir(false), channel));
    }
}

#[test]
fn data_channels_occupy_the_expected_dlci_range() {
    assert_eq!(u::dlci(0, u::RFCOMM_CHANNEL_MIN), 2);
    assert_eq!(u::dlci(1, u::RFCOMM_CHANNEL_MAX), 61);
    assert!(!u::channel_valid(0));
    assert!(!u::channel_valid(31));
}

#[test]
fn command_frames_round_trip() {
    for ftype in [u::RFCOMM_SABM, u::RFCOMM_DISC, u::RFCOMM_UA, u::RFCOMM_DM] {
        let f = frame::encode_cmd(u::addr(true, 4), ftype, true);
        assert_eq!(f.len(), FRAME_MIN_LEN);
        let d = frame::decode(&f).expect("valid frame");
        assert_eq!(d.ftype(), ftype);
        assert!(d.pf());
        assert_eq!(d.dlci(), 4);
        assert!(d.payload.is_empty());
        assert_eq!(d.declared_len, 0);
    }
}

#[test]
fn uih_frames_round_trip_and_the_length_field_widens() {
    let short = alloc::vec![0xaa; 10];
    let f = frame::encode_uih(u::addr(true, 6), false, &short);
    let d = frame::decode(&f).expect("valid frame");
    assert_eq!(d.declared_len, 10);
    assert_eq!(d.payload, &short[..]);
    assert_eq!(f.len(), 10 + 4);

    let long = alloc::vec![0x5a; 300];
    let f = frame::encode_uih(u::addr(true, 6), false, &long);
    assert_eq!(f.len(), 300 + 5, "a long frame carries a two-byte length");
    assert!(!u::test_ea(f[2]));
    let d = frame::decode(&f).expect("valid frame");
    assert_eq!(d.declared_len, 300);
    assert_eq!(d.payload, &long[..]);
}

#[test]
fn the_widest_one_byte_length_stays_one_byte() {
    let p = alloc::vec![1u8; u::RFCOMM_LEN8_MAX];
    let f = frame::encode_uih(u::addr(true, 2), false, &p);
    assert!(u::test_ea(f[2]));
    assert_eq!(frame::decode(&f).unwrap().declared_len, u::RFCOMM_LEN8_MAX);
}

#[test]
fn a_corrupted_frame_is_refused() {
    let mut f = frame::encode_cmd(u::addr(true, 4), u::RFCOMM_SABM, true);
    f[0] ^= 0x04;
    assert_eq!(frame::decode(&f), Err(FrameError::BadFcs));

    let mut f = frame::encode_uih(u::addr(true, 4), false, &[1, 2, 3]);
    let last = f.len() - 1;
    f[last] ^= 0xff;
    assert_eq!(frame::decode(&f), Err(FrameError::BadFcs));
}

#[test]
fn a_short_frame_is_refused() {
    assert_eq!(frame::decode(&[0x03, 0xef, 0x01]), Err(FrameError::Truncated));
    assert_eq!(frame::decode(&[]), Err(FrameError::Truncated));
}

#[test]
fn the_poll_bit_is_visible_on_a_data_frame() {
    let f = frame::encode_uih(u::addr(true, 4), true, &[7]);
    let d = frame::decode(&f).unwrap();
    assert!(d.pf());
    assert!(d.is_uih());
}
