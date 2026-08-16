//! Socket-surface contract: state windows, the link-mode mapping in both
//! directions, and the listener table.

use crate::rfcomm::sock::{self, Listeners, RfcommSock};
use crate::rfcomm::sockopt::{self, Conninfo};
use crate::uapi::bt::{BdAddr, AF_BLUETOOTH, BT_BOUND, BT_CONNECT, BT_CONNECTED, BT_LISTEN,
                      BT_OPEN, BT_SECURITY_FIPS, BT_SECURITY_HIGH, BT_SECURITY_LOW,
                      BT_SECURITY_MEDIUM, BT_SECURITY_SDP};
use crate::uapi::rfcomm as u;
use syscall::errno::Errno;

fn sa(channel: u8) -> u::SockaddrRc {
    u::SockaddrRc { family: AF_BLUETOOTH as u16, bdaddr: BdAddr([1, 2, 3, 4, 5, 6]), channel }
}

#[test]
fn the_address_round_trips_through_its_abi_layout() {
    let a = sa(7);
    let mut buf = [0xffu8; u::SOCKADDR_RC_LEN];
    assert!(a.to_wire(&mut buf));
    assert_eq!(u::SockaddrRc::from_wire(&buf), Some(a));
    assert!(u::SockaddrRc::from_wire(&buf[..u::SOCKADDR_RC_LEN - 1]).is_none());
}

#[test]
fn bind_demands_a_fresh_stream_socket() {
    let mut sk = RfcommSock::new(true);
    let l = Listeners::new();
    assert!(sock::bind(&mut sk, &sa(1), &l).is_ok());
    assert_eq!(sk.state, BT_BOUND);
    assert_eq!(sock::bind(&mut sk, &sa(1), &l), Err(Errno::Ebadfd));

    let mut dgram = RfcommSock::new(false);
    assert_eq!(sock::bind(&mut dgram, &sa(1), &l), Err(Errno::Einval));

    let mut sk = RfcommSock::new(true);
    let mut wrong = sa(1);
    wrong.family = 0;
    assert_eq!(sock::bind(&mut sk, &wrong, &l), Err(Errno::Einval));
}

#[test]
fn a_taken_channel_collides_and_channel_zero_does_not() {
    let mut l = Listeners::new();
    l.add(4, BdAddr([1, 2, 3, 4, 5, 6]));
    let mut sk = RfcommSock::new(true);
    assert_eq!(sock::bind(&mut sk, &sa(4), &l), Err(Errno::Eaddrinuse));
    let mut sk = RfcommSock::new(true);
    assert!(sock::bind(&mut sk, &sa(0), &l).is_ok(), "channel zero claims nothing");
}

#[test]
fn listen_picks_the_first_free_channel_for_a_socket_bound_without_one() {
    let mut l = Listeners::new();
    let mut sk = RfcommSock::new(true);
    sock::bind(&mut sk, &sa(0), &l).unwrap();
    sock::listen(&mut sk, 5, &mut l).unwrap();
    assert_eq!(sk.channel, u::RFCOMM_CHANNEL_MIN);
    assert_eq!(sk.state, BT_LISTEN);

    let mut sk2 = RfcommSock::new(true);
    sock::bind(&mut sk2, &sa(0), &l).unwrap();
    sock::listen(&mut sk2, 5, &mut l).unwrap();
    assert_eq!(sk2.channel, u::RFCOMM_CHANNEL_MIN + 1);
}

#[test]
fn listen_fails_when_every_channel_is_taken() {
    let mut l = Listeners::new();
    let addr = BdAddr([1, 2, 3, 4, 5, 6]);
    for c in u::RFCOMM_CHANNEL_MIN..=u::RFCOMM_CHANNEL_MAX { l.add(c, addr); }
    let mut sk = RfcommSock::new(true);
    sk.state = BT_BOUND;
    sk.src = addr;
    assert_eq!(sock::listen(&mut sk, 1, &mut l), Err(Errno::Einval));
}

#[test]
fn listen_demands_a_bound_socket_and_close_releases_the_channel() {
    let mut l = Listeners::new();
    let mut sk = RfcommSock::new(true);
    assert_eq!(sock::listen(&mut sk, 1, &mut l), Err(Errno::Ebadfd));
    sock::bind(&mut sk, &sa(9), &l).unwrap();
    sock::listen(&mut sk, 1, &mut l).unwrap();
    assert!(l.taken(9, sk.src));
    sock::close(&mut sk, &mut l);
    assert!(!l.taken(9, BdAddr([1, 2, 3, 4, 5, 6])));
}

#[test]
fn connect_validates_the_channel_and_the_state() {
    let mut sk = RfcommSock::new(true);
    assert_eq!(sock::connect(&mut sk, &sa(0)), Err(Errno::Einval));
    assert_eq!(sock::connect(&mut sk, &sa(31)), Err(Errno::Einval));
    assert!(sock::connect(&mut sk, &sa(4)).is_ok());
    assert_eq!(sk.state, BT_CONNECT);
    assert_eq!(sock::connect(&mut sk, &sa(4)), Err(Errno::Ebadfd));
}

#[test]
fn the_link_mode_word_maps_onto_the_security_level() {
    let mut sk = RfcommSock::new(true);
    sockopt::set_lm(&mut sk, u::RFCOMM_LM_AUTH).unwrap();
    assert_eq!(sk.sec_level, BT_SECURITY_LOW);
    sockopt::set_lm(&mut sk, u::RFCOMM_LM_ENCRYPT).unwrap();
    assert_eq!(sk.sec_level, BT_SECURITY_MEDIUM);
    sockopt::set_lm(&mut sk, u::RFCOMM_LM_SECURE).unwrap();
    assert_eq!(sk.sec_level, BT_SECURITY_HIGH);
    // The bits are not exclusive: the highest one present decides.
    sockopt::set_lm(&mut sk, u::RFCOMM_LM_AUTH | u::RFCOMM_LM_ENCRYPT).unwrap();
    assert_eq!(sk.sec_level, BT_SECURITY_MEDIUM);
    sockopt::set_lm(&mut sk, u::RFCOMM_LM_AUTH | u::RFCOMM_LM_SECURE).unwrap();
    assert_eq!(sk.sec_level, BT_SECURITY_HIGH);
}

#[test]
fn the_link_mode_word_refuses_the_fips_bit_and_carries_the_role_switch() {
    let mut sk = RfcommSock::new(true);
    assert_eq!(sockopt::set_lm(&mut sk, u::RFCOMM_LM_FIPS), Err(Errno::Einval));
    assert_eq!(sockopt::set_lm(&mut sk, u::RFCOMM_LM_FIPS | u::RFCOMM_LM_AUTH), Err(Errno::Einval));
    assert!(!sk.role_switch);
    sockopt::set_lm(&mut sk, u::RFCOMM_LM_MASTER).unwrap();
    assert!(sk.role_switch);
    sockopt::set_lm(&mut sk, u::RFCOMM_LM_AUTH).unwrap();
    assert!(!sk.role_switch, "the role switch follows the word it was set with");
}

#[test]
fn the_link_mode_word_is_reconstructed_from_the_level() {
    let mut sk = RfcommSock::new(true);
    let cases = [
        (BT_SECURITY_SDP, 0),
        (BT_SECURITY_LOW, u::RFCOMM_LM_AUTH),
        (BT_SECURITY_MEDIUM, u::RFCOMM_LM_AUTH | u::RFCOMM_LM_ENCRYPT),
        (BT_SECURITY_HIGH, u::RFCOMM_LM_AUTH | u::RFCOMM_LM_ENCRYPT | u::RFCOMM_LM_SECURE),
        (BT_SECURITY_FIPS, u::RFCOMM_LM_AUTH | u::RFCOMM_LM_ENCRYPT | u::RFCOMM_LM_SECURE | u::RFCOMM_LM_FIPS),
    ];
    for (level, word) in cases {
        sk.sec_level = level;
        assert_eq!(sockopt::get_lm(&sk), word);
    }
    sk.role_switch = true;
    assert_eq!(sockopt::get_lm(&sk) & u::RFCOMM_LM_MASTER, u::RFCOMM_LM_MASTER);
}

#[test]
fn the_security_level_tops_out_below_fips() {
    let mut sk = RfcommSock::new(true);
    for level in [BT_SECURITY_SDP, BT_SECURITY_LOW, BT_SECURITY_MEDIUM, BT_SECURITY_HIGH] {
        assert!(sockopt::set_security(&mut sk, level).is_ok());
        assert_eq!(sockopt::get_security(&sk), Ok((level, 0)));
    }
    assert_eq!(sockopt::set_security(&mut sk, BT_SECURITY_FIPS), Err(Errno::Einval));
    let mut dgram = RfcommSock::new(false);
    assert_eq!(sockopt::set_security(&mut dgram, BT_SECURITY_LOW), Err(Errno::Einval));
    assert_eq!(sockopt::get_security(&dgram), Err(Errno::Einval));
}

#[test]
fn deferral_is_settable_only_while_bound_or_listening() {
    let mut sk = RfcommSock::new(true);
    for state in [BT_OPEN, BT_CONNECT, BT_CONNECTED] {
        sk.state = state;
        assert_eq!(sockopt::set_defer_setup(&mut sk, true), Err(Errno::Einval));
        assert_eq!(sockopt::get_defer_setup(&sk), Err(Errno::Einval));
    }
    for state in [BT_BOUND, BT_LISTEN] {
        sk.state = state;
        assert!(sockopt::set_defer_setup(&mut sk, true).is_ok());
        assert_eq!(sockopt::get_defer_setup(&sk), Ok(true));
    }
}

#[test]
fn connection_info_needs_a_connection_or_a_deferred_one() {
    let mut sk = RfcommSock::new(true);
    let info = Conninfo { hci_handle: 0x2a, dev_class: [1, 2, 3] };
    sk.state = BT_BOUND;
    assert_eq!(sockopt::get_conninfo(&sk, false, info), Err(Errno::Enotconn));
    assert_eq!(sockopt::get_conninfo(&sk, true, info), Ok(info));
    sk.state = BT_CONNECTED;
    assert_eq!(sockopt::get_conninfo(&sk, false, info), Ok(info));

    let mut buf = [0u8; u::RFCOMM_CONNINFO_LEN];
    assert!(info.to_wire(&mut buf));
    assert_eq!(&buf[..2], &0x2au16.to_le_bytes());
    assert_eq!(&buf[2..5], &[1, 2, 3]);
    assert!(!info.to_wire(&mut buf[..1]));
}

#[test]
fn the_option_numbers_are_the_ones_the_abi_defines() {
    assert!(sockopt::sol_rfcomm_known(u::RFCOMM_LM));
    assert!(sockopt::sol_rfcomm_known(u::RFCOMM_CONNINFO));
    assert!(!sockopt::sol_rfcomm_known(0x01));
    assert_eq!(crate::uapi::bt::SOL_RFCOMM, 18);
}
