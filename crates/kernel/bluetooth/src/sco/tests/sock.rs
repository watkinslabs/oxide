//! Socket-surface contract: every option's state window and errno.

use crate::sco::sock::{self, Conninfo, ScoSock};
use crate::uapi::bt::{BdAddr, AF_BLUETOOTH, BT_BOUND, BT_CLOSED, BT_CONNECT, BT_CONNECT2,
                      BT_CONNECTED, BT_LISTEN, BT_OPEN, BT_VOICE_CVSD_16BIT,
                      BT_VOICE_TRANSPARENT};
use crate::uapi::sco as u;
use syscall::errno::Errno;

fn sa() -> u::SockaddrSco {
    u::SockaddrSco { family: AF_BLUETOOTH as u16, bdaddr: BdAddr([1, 2, 3, 4, 5, 6]) }
}

#[test]
fn the_address_round_trips_through_its_abi_layout() {
    let a = sa();
    let mut buf = [0u8; u::SOCKADDR_SCO_LEN];
    assert!(a.to_wire(&mut buf));
    assert_eq!(u::SockaddrSco::from_wire(&buf), Some(a));
    assert_eq!(u::SOCKADDR_SCO_LEN, 8);
    assert!(u::SockaddrSco::from_wire(&buf[..7]).is_none());
}

#[test]
fn a_new_socket_asks_for_the_variable_slope_coding() {
    let sk = ScoSock::new();
    assert_eq!(sk.setting, BT_VOICE_CVSD_16BIT);
    assert_eq!(sk.codec.id, u::BT_CODEC_CVSD);
    assert_eq!(sk.mtu, u::SCO_DEFAULT_MTU);
    assert_eq!(sk.state, BT_OPEN);
}

#[test]
fn bind_connect_and_listen_walk_the_states() {
    let mut sk = ScoSock::new();
    assert!(sock::bind(&mut sk, &sa()).is_ok());
    assert_eq!(sk.state, BT_BOUND);
    assert_eq!(sock::bind(&mut sk, &sa()), Err(Errno::Ebadfd));
    assert!(sock::listen(&mut sk).is_ok());
    assert_eq!(sk.state, BT_LISTEN);
    assert_eq!(sock::listen(&mut sk), Err(Errno::Ebadfd));

    let mut sk = ScoSock::new();
    assert!(sock::connect(&mut sk, &sa()).is_ok());
    assert_eq!(sk.state, BT_CONNECT);
    assert_eq!(sock::connect(&mut sk, &sa()), Err(Errno::Ebadfd));
    sock::close(&mut sk);
    assert_eq!(sk.state, BT_CLOSED);

    let mut sk = ScoSock::new();
    let mut wrong = sa();
    wrong.family = 0;
    assert_eq!(sock::bind(&mut sk, &wrong), Err(Errno::Einval));
    assert_eq!(sock::connect(&mut sk, &wrong), Err(Errno::Einval));
}

#[test]
fn the_voice_setting_moves_only_before_there_is_a_link() {
    let mut sk = ScoSock::new();
    for state in [BT_OPEN, BT_BOUND, BT_CONNECT2] {
        sk.state = state;
        assert!(sock::set_voice(&mut sk, BT_VOICE_TRANSPARENT).is_ok());
        assert_eq!(sock::get_voice(&sk), BT_VOICE_TRANSPARENT);
    }
    for state in [BT_CONNECT, BT_CONNECTED, BT_LISTEN, BT_CLOSED] {
        sk.state = state;
        assert_eq!(sock::set_voice(&mut sk, BT_VOICE_CVSD_16BIT), Err(Errno::Einval));
        assert_eq!(sock::get_voice(&sk), BT_VOICE_TRANSPARENT, "and is readable in any state");
    }
}

#[test]
fn transparent_coding_selects_the_transparent_codec_with_it() {
    let mut sk = ScoSock::new();
    sock::set_voice(&mut sk, BT_VOICE_TRANSPARENT).unwrap();
    assert_eq!(sk.codec.id, u::BT_CODEC_TRANSPARENT);
    sock::set_voice(&mut sk, BT_VOICE_CVSD_16BIT).unwrap();
    assert_eq!(sk.codec.id, u::BT_CODEC_CVSD);
}

#[test]
fn the_codec_option_takes_exactly_one_codec() {
    let mut sk = ScoSock::new();
    let c = u::BtCodec { id: u::BT_CODEC_MSBC, cid: 0, vid: 0, data_path: 1, num_caps: 0 };
    assert_eq!(sock::set_codec(&mut sk, 0, None), Err(Errno::Einval));
    assert_eq!(sock::set_codec(&mut sk, 2, Some(c)), Err(Errno::Einval));
    assert!(sock::set_codec(&mut sk, 1, Some(c)).is_ok());
    assert_eq!(sk.codec, c);
    sk.state = BT_CONNECTED;
    assert_eq!(sock::set_codec(&mut sk, 1, Some(c)), Err(Errno::Einval));
}

#[test]
fn the_codec_struct_round_trips_packed() {
    let c = u::BtCodec { id: 5, cid: 0x0102, vid: 0x0304, data_path: 1, num_caps: 2 };
    let mut buf = [0u8; u::BT_CODEC_LEN];
    assert!(c.to_wire(&mut buf));
    assert_eq!(u::BT_CODEC_LEN, 7, "the descriptor is packed, not aligned");
    assert_eq!(u::BtCodec::from_wire(&buf), Some(c));
    assert!(u::BtCodec::from_wire(&buf[..6]).is_none());
}

#[test]
fn deferral_is_settable_only_while_bound_or_listening() {
    let mut sk = ScoSock::new();
    for state in [BT_OPEN, BT_CONNECT, BT_CONNECT2, BT_CONNECTED] {
        sk.state = state;
        assert_eq!(sock::set_defer_setup(&mut sk, true), Err(Errno::Einval));
        assert_eq!(sock::get_defer_setup(&sk), Err(Errno::Einval));
    }
    for state in [BT_BOUND, BT_LISTEN] {
        sk.state = state;
        assert!(sock::set_defer_setup(&mut sk, true).is_ok());
        assert_eq!(sock::get_defer_setup(&sk), Ok(true));
    }
}

#[test]
fn the_packet_status_request_is_settable_in_any_state() {
    let mut sk = ScoSock::new();
    for state in [BT_OPEN, BT_BOUND, BT_LISTEN, BT_CONNECT, BT_CONNECT2, BT_CONNECTED, BT_CLOSED] {
        sk.state = state;
        sock::set_pkt_status(&mut sk, true);
        assert!(sock::get_pkt_status(&sk));
        sock::set_pkt_status(&mut sk, false);
        assert!(!sock::get_pkt_status(&sk));
    }
}

#[test]
fn the_link_options_need_a_link_or_a_deferred_one() {
    let mut sk = ScoSock::new();
    let info = Conninfo { hci_handle: 0x2a, dev_class: [1, 2, 3] };
    for state in [BT_OPEN, BT_BOUND, BT_LISTEN, BT_CONNECT] {
        sk.state = state;
        assert_eq!(sock::get_options(&sk), Err(Errno::Enotconn));
        assert_eq!(sock::get_conninfo(&sk, info), Err(Errno::Enotconn));
        assert_eq!(sock::get_mtu(&sk), Err(Errno::Enotconn));
    }
    sk.state = BT_CONNECT2;
    assert_eq!(sock::get_options(&sk), Err(Errno::Enotconn), "without deferral there is nothing to report");
    sk.defer_setup = true;
    assert_eq!(sock::get_options(&sk), Ok(u::SCO_DEFAULT_MTU));
    assert_eq!(sock::get_conninfo(&sk, info), Ok(info));
    assert_eq!(sock::get_mtu(&sk), Err(Errno::Enotconn), "the send ceiling needs a live link");

    sk.state = BT_CONNECTED;
    sk.mtu = 60;
    assert_eq!(sock::get_options(&sk), Ok(60));
    assert_eq!(sock::get_mtu(&sk), Ok(60));
}

#[test]
fn the_connection_info_encodes_at_its_abi_width() {
    let info = Conninfo { hci_handle: 0x2a, dev_class: [1, 2, 3] };
    let mut buf = [0xffu8; u::SCO_CONNINFO_LEN];
    assert!(info.to_wire(&mut buf));
    assert_eq!(u::SCO_CONNINFO_LEN, 6);
    assert_eq!(&buf[0..2], &0x2au16.to_le_bytes());
    assert_eq!(&buf[2..5], &[1, 2, 3]);
    assert_eq!(buf[5], 0, "the tail padding is zeroed");
    assert!(!info.to_wire(&mut buf[..5]));
}

#[test]
fn the_option_numbers_are_the_ones_the_abi_defines() {
    assert_eq!(u::SCO_OPTIONS, 0x01);
    assert_eq!(u::SCO_CONNINFO, 0x02);
    assert_eq!(crate::uapi::bt::SOL_SCO, 17);
    assert_eq!(u::SCO_DEFAULT_MTU, 500);
}
