//! The socket surface: multiplexer validity and the privileged range, the
//! address layout, and the order in which the options refuse.

use super::*;
use crate::uapi::bt::{BT_SECURITY_HIGH, BT_SECURITY_MEDIUM, BT_SECURITY_SDP};

fn addr(psm: u16, cid: u16, t: u8) -> SockAddrL2 {
    SockAddrL2 { family: AF_BLUETOOTH as u16, psm, bdaddr: BdAddr::default(), cid, bdaddr_type: t }
}

#[test]
fn an_address_round_trips_at_its_declared_width() {
    let a = SockAddrL2 { family: AF_BLUETOOTH as u16, psm: 0x1001, bdaddr: BdAddr([1, 2, 3, 4, 5, 6]), cid: 0x0040, bdaddr_type: BDADDR_LE_PUBLIC };
    let b = a.encode();
    assert_eq!(b.len(), u::SOCKADDR_L2_LEN);
    assert_eq!(SockAddrL2::decode(&b), Some(a));
    // The fields sit where the layout says.
    assert_eq!(&b[u::SOCKADDR_L2_BDADDR_OFF..u::SOCKADDR_L2_BDADDR_OFF + 6], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(b[u::SOCKADDR_L2_BDADDR_TYPE_OFF], BDADDR_LE_PUBLIC);
}

#[test]
fn a_short_address_reads_its_missing_fields_as_zero() {
    let a = addr(0x1001, 0, BDADDR_BREDR);
    let short = &a.encode()[..8];
    let back = SockAddrL2::decode(short).unwrap();
    assert_eq!(back.psm, 0x1001);
    assert_eq!(back.cid, 0);
    assert_eq!(back.bdaddr_type, BDADDR_BREDR);
    assert!(SockAddrL2::decode(&[0]).is_none());
}

#[test]
fn a_bredr_multiplexer_must_be_odd_with_a_clear_upper_low_bit() {
    assert!(bredr_psm_well_formed(u::PSM_SDP));
    assert!(bredr_psm_well_formed(u::PSM_RFCOMM));
    assert!(bredr_psm_well_formed(0x1001));
    assert!(!bredr_psm_well_formed(0));
    assert!(!bredr_psm_well_formed(0x0002));
    assert!(!bredr_psm_well_formed(0x0101));
}

#[test]
fn an_le_multiplexer_must_be_inside_the_defined_range() {
    assert!(le_psm_well_formed(1));
    assert!(le_psm_well_formed(u::PSM_LE_DYN_END));
    assert!(!le_psm_well_formed(0));
    assert!(!le_psm_well_formed(u::PSM_LE_DYN_END + 1));
    // Both transports use their own rule, not each other's.
    assert!(psm_valid(0x0080, true));
    assert!(!psm_valid(0x0080, false));
    assert!(psm_valid(0x1001, false));
    assert!(!psm_valid(0x1001, true));
}

#[test]
fn a_well_known_bredr_multiplexer_needs_the_bind_service_capability() {
    assert_eq!(validate_bredr_psm(u::PSM_SDP, false), Err(Errno::Eacces));
    assert_eq!(validate_bredr_psm(u::PSM_SDP, true), Ok(()));
    assert_eq!(validate_bredr_psm(u::PSM_DYN_START, false), Ok(()));
    // A well-formed value inside the assigned range is still privileged.
    assert!(bredr_psm_well_formed(0x0e01) && 0x0e01 < u::PSM_DYN_START);
    assert_eq!(validate_bredr_psm(0x0e01, false), Err(Errno::Eacces));
    assert_eq!(validate_bredr_psm(0x0e01, true), Ok(()));
}

#[test]
fn a_malformed_multiplexer_is_reported_as_wrong_before_it_is_reported_as_privileged() {
    // A value that is both malformed and inside the privileged range must
    // report the malformation, not the privilege.
    assert_eq!(validate_bredr_psm(0x0002, false), Err(Errno::Einval));
    assert_eq!(validate_bredr_psm(0x0002, true), Err(Errno::Einval));
}

#[test]
fn a_well_known_le_multiplexer_needs_the_bind_service_capability() {
    assert_eq!(validate_le_psm(0x001f, false), Err(Errno::Eacces));
    assert_eq!(validate_le_psm(0x001f, true), Ok(()));
    assert_eq!(validate_le_psm(u::PSM_LE_DYN_START, false), Ok(()));
    assert_eq!(validate_le_psm(u::PSM_LE_DYN_END + 1, true), Err(Errno::Einval));
}

#[test]
fn a_bind_naming_both_a_multiplexer_and_a_channel_is_ambiguous() {
    assert_eq!(validate_bind(&addr(0x1001, 0x0040, BDADDR_BREDR), BT_OPEN, true), Err(Errno::Einval));
}

#[test]
fn a_bind_is_refused_in_any_state_but_the_unbound_one() {
    let a = addr(0x1001, 0, BDADDR_BREDR);
    assert_eq!(validate_bind(&a, BT_OPEN, true), Ok(()));
    assert_eq!(validate_bind(&a, BT_BOUND, true), Err(Errno::Ebadfd));
    assert_eq!(validate_bind(&a, BT_CONNECTED, true), Err(Errno::Ebadfd));
}

#[test]
fn a_bind_with_a_wrong_family_or_address_type_is_refused() {
    let mut a = addr(0x1001, 0, BDADDR_BREDR);
    a.family = 0;
    assert_eq!(validate_bind(&a, BT_OPEN, true), Err(Errno::Einval));
    let bad_type = addr(0x1001, 0, 9);
    assert_eq!(validate_bind(&bad_type, BT_OPEN, true), Err(Errno::Einval));
}

#[test]
fn only_the_attribute_channel_is_bindable_by_identifier_on_an_le_link() {
    assert_eq!(validate_bind(&addr(0, u::CID_ATT, BDADDR_LE_PUBLIC), BT_OPEN, true), Ok(()));
    assert_eq!(validate_bind(&addr(0, 0x0040, BDADDR_LE_PUBLIC), BT_OPEN, true), Err(Errno::Einval));
    // A BR/EDR link has no such restriction.
    assert_eq!(validate_bind(&addr(0, 0x0040, BDADDR_BREDR), BT_OPEN, true), Ok(()));
}

#[test]
fn binding_a_pre_pairing_service_lowers_the_level_it_implies() {
    assert_eq!(bind_sec_level(u::CHAN_CONN_ORIENTED, u::PSM_SDP), Some(BT_SECURITY_SDP));
    assert_eq!(bind_sec_level(u::CHAN_CONN_ORIENTED, u::PSM_RFCOMM), Some(BT_SECURITY_SDP));
    assert_eq!(bind_sec_level(u::CHAN_CONN_LESS, u::PSM_3DSP), Some(BT_SECURITY_SDP));
    assert_eq!(bind_sec_level(u::CHAN_RAW, 0x1001), Some(BT_SECURITY_SDP));
    assert_eq!(bind_sec_level(u::CHAN_CONN_ORIENTED, 0x1001), None);
}

#[test]
fn a_receive_mtu_has_a_floor_that_depends_on_the_channel() {
    assert!(valid_mtu(u::CID_ATT, u::LE_MIN_MTU));
    assert!(!valid_mtu(u::CID_ATT, u::LE_MIN_MTU - 1));
    assert!(valid_mtu(0x0040, u::DEFAULT_MIN_MTU));
    assert!(!valid_mtu(0x0040, u::DEFAULT_MIN_MTU - 1));
    assert!(valid_mtu(0x0040, 0));
}

#[test]
fn the_legacy_option_payload_round_trips_through_its_padding() {
    let o = L2capOptions { omtu: 672, imtu: 512, flush_to: 0xffff, mode: u::MODE_ERTM, fcs: 1, max_tx: 3, txwin_size: 63 };
    let b = o.encode();
    assert_eq!(b.len(), u::L2CAP_OPTIONS_LEN);
    assert_eq!(L2capOptions::decode(&b), Some(o));
    assert!(L2capOptions::decode(&b[..u::L2CAP_OPTIONS_LEN - 1]).is_none());
}

#[test]
fn the_legacy_option_refuses_in_order_and_changes_nothing_when_it_does() {
    let mut c = Channel::new();
    let before = c.clone();
    // An LE channel has no legacy options at all.
    c.dst_type = BDADDR_LE_PUBLIC;
    assert_eq!(set_l2cap_options(&mut c, BT_OPEN, &L2capOptions::of(&before)), Err(Errno::Einval));
    c.dst_type = BDADDR_BREDR;
    // An open channel cannot be reconfigured this way.
    assert_eq!(set_l2cap_options(&mut c, BT_CONNECTED, &L2capOptions::of(&before)), Err(Errno::Einval));
    // A window past the widest field.
    let mut o = L2capOptions::of(&before);
    o.txwin_size = u::DEFAULT_EXT_WINDOW + 1;
    assert_eq!(set_l2cap_options(&mut c, BT_OPEN, &o), Err(Errno::Einval));
    // An unusable receive MTU.
    let mut o = L2capOptions::of(&before);
    o.imtu = 1;
    assert_eq!(set_l2cap_options(&mut c, BT_OPEN, &o), Err(Errno::Einval));
    // A mode this option cannot describe.
    let mut o = L2capOptions::of(&before);
    o.mode = u::MODE_LE_FLOWCTL;
    assert_eq!(set_l2cap_options(&mut c, BT_OPEN, &o), Err(Errno::Einval));
    assert_eq!(c, before);
}

#[test]
fn the_legacy_option_applies_every_field_it_carries() {
    let mut c = Channel::new();
    let o = L2capOptions { omtu: 700, imtu: 600, flush_to: 100, mode: u::MODE_ERTM, fcs: u::FCS_NONE, max_tx: 5, txwin_size: 40 };
    assert_eq!(set_l2cap_options(&mut c, BT_OPEN, &o), Ok(()));
    assert_eq!(L2capOptions::of(&c), o);
    assert_eq!(get_l2cap_options(&c), Ok(o));
}

#[test]
fn the_legacy_option_cannot_describe_a_credit_mode_channel() {
    let mut c = Channel::new();
    c.mode = u::MODE_LE_FLOWCTL;
    assert_eq!(get_l2cap_options(&c), Err(Errno::Einval));
    // The attribute channel is readable even on an LE link.
    c.dst_type = BDADDR_LE_PUBLIC;
    c.scid = u::CID_ATT;
    c.mode = u::MODE_BASIC;
    assert!(get_l2cap_options(&c).is_ok());
    c.scid = 0x0040;
    assert_eq!(get_l2cap_options(&c), Err(Errno::Einval));
}

#[test]
fn each_mode_belongs_to_one_transport() {
    let mut c = Channel::new();
    assert_eq!(set_bt_mode(&mut c, BT_BOUND, BT_MODE_ERTM), Ok(()));
    assert_eq!(c.mode, u::MODE_ERTM);
    assert_eq!(set_bt_mode(&mut c, BT_BOUND, BT_MODE_LE_FLOWCTL), Err(Errno::Einval));
    c.dst_type = BDADDR_LE_PUBLIC;
    assert_eq!(set_bt_mode(&mut c, BT_BOUND, BT_MODE_EXT_FLOWCTL), Ok(()));
    assert_eq!(c.mode, u::MODE_EXT_FLOWCTL);
    assert_eq!(set_bt_mode(&mut c, BT_BOUND, BT_MODE_BASIC), Err(Errno::Einval));
    // Only before the channel is used, and only on a connection-oriented one.
    assert_eq!(set_bt_mode(&mut c, BT_CONNECTED, BT_MODE_LE_FLOWCTL), Err(Errno::Einval));
    c.chan_type = u::CHAN_FIXED;
    assert_eq!(set_bt_mode(&mut c, BT_BOUND, BT_MODE_LE_FLOWCTL), Err(Errno::Einval));
}

#[test]
fn a_security_level_must_name_a_defined_level_on_a_channel_that_has_one() {
    let mut c = Channel::new();
    assert_eq!(set_security(&mut c, BT_SECURITY_MEDIUM), Ok(()));
    assert_eq!(c.sec_level, BT_SECURITY_MEDIUM);
    assert_eq!(set_security(&mut c, BT_SECURITY_FIPS + 1), Err(Errno::Einval));
    assert_eq!(c.sec_level, BT_SECURITY_MEDIUM);
    c.chan_type = u::CHAN_CONN_LESS;
    assert_eq!(set_security(&mut c, BT_SECURITY_HIGH), Err(Errno::Einval));
}

#[test]
fn deferred_setup_may_only_change_before_a_connection_can_arrive() {
    assert_eq!(set_defer_setup(BT_BOUND), Ok(()));
    assert_eq!(set_defer_setup(BT_LISTEN), Ok(()));
    assert_eq!(set_defer_setup(BT_CONNECTED), Err(Errno::Einval));
}

#[test]
fn the_send_mtu_is_fixed_once_the_channel_is_open() {
    let mut c = Channel::new();
    assert_eq!(set_sndmtu(&mut c, BT_BOUND, 512), Err(Errno::Einval));
    c.dst_type = BDADDR_LE_PUBLIC;
    assert_eq!(set_sndmtu(&mut c, BT_BOUND, 512), Ok(()));
    assert_eq!(c.omtu, 512);
    assert_eq!(set_sndmtu(&mut c, BT_CONNECTED, 256), Err(Errno::Eisconn));
}

#[test]
fn the_receive_mtu_can_be_renegotiated_only_in_the_enhanced_credit_mode() {
    let mut c = Channel::new();
    c.dst_type = BDADDR_LE_PUBLIC;
    c.mode = u::MODE_LE_FLOWCTL;
    assert_eq!(set_rcvmtu(&mut c, BT_BOUND, 512), Ok(RcvMtu::Stored));
    assert_eq!(set_rcvmtu(&mut c, BT_CONNECTED, 512), Err(Errno::Eisconn));
    c.mode = u::MODE_EXT_FLOWCTL;
    assert_eq!(set_rcvmtu(&mut c, BT_CONNECTED, 512), Ok(RcvMtu::Reconfigure(512)));
    assert_eq!(set_rcvmtu(&mut c, BT_CONNECTED, u::ECRED_MIN_MTU - 1), Err(Errno::Einval));
}

#[test]
fn connection_info_needs_a_link_to_describe() {
    assert_eq!(conninfo_readable(BT_CONNECTED, false), Ok(()));
    assert_eq!(conninfo_readable(BT_CONNECT2, true), Ok(()));
    assert_eq!(conninfo_readable(BT_CONNECT2, false), Err(Errno::Enotconn));
    assert_eq!(conninfo_readable(BT_BOUND, true), Err(Errno::Enotconn));
    let b = encode_conninfo(0x0042, [1, 2, 3]);
    assert_eq!(b.len(), u::L2CAP_CONNINFO_LEN);
    assert_eq!(&b[..2], &0x0042u16.to_le_bytes());
    assert_eq!(&b[2..5], &[1, 2, 3]);
}

#[test]
fn only_the_two_option_levels_this_protocol_answers_are_accepted() {
    assert_eq!(level_supported(crate::uapi::bt::SOL_L2CAP), Ok(()));
    assert_eq!(level_supported(crate::uapi::bt::SOL_BLUETOOTH), Ok(()));
    assert_eq!(level_supported(0), Err(Errno::Enoprotoopt));
}
