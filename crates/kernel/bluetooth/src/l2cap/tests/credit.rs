//! Credit accounting: no credit means no transmission, a grant releases it, and
//! a grant past the ceiling ends the channel.

use super::*;
use crate::uapi::bt::BT_CONNECTED;
use alloc::vec;

fn credit_chan() -> Channel {
    let mut c = Channel::new();
    c.state = BT_CONNECTED;
    c.mode = u::MODE_LE_FLOWCTL;
    c.imtu = 512;
    le_flowctl_init(&mut c, 0, 251);
    c
}

#[test]
fn setup_derives_the_pdu_size_from_the_link_and_grants_the_peer_credits() {
    let c = credit_chan();
    assert_eq!(c.mps, 251 - u::HDR_SIZE as u16);
    assert!(c.rx_credits > 0);
    assert_eq!(c.tx_credits, 0);
}

#[test]
fn the_enhanced_variant_raises_the_pdu_floor() {
    let mut c = Channel::new();
    c.mode = u::MODE_EXT_FLOWCTL;
    c.imtu = 512;
    ecred_init(&mut c, 3, 20);
    assert_eq!(c.mps, u::ECRED_MIN_MPS);
    assert_eq!(c.tx_credits, 3);
}

#[test]
fn no_credit_blocks_transmission_and_a_grant_releases_it() {
    let mut c = credit_chan();
    let mut queue = vec![vec![1u8], vec![2u8], vec![3u8]];
    assert!(!can_transmit(&c));
    assert!(drain_tx(&mut c, &mut queue).is_empty());
    assert_eq!(queue.len(), 3);

    assert_eq!(grant_credits(&mut c, 2), Grant::Applied(2));
    assert!(can_transmit(&c));
    let sent = drain_tx(&mut c, &mut queue);
    assert_eq!(sent.len(), 2);
    assert_eq!(queue.len(), 1);
    assert_eq!(c.tx_credits, 0);
    assert!(!can_transmit(&c));
}

#[test]
fn spending_a_credit_reports_whether_there_was_one() {
    let mut c = credit_chan();
    assert!(!spend_credit(&mut c));
    grant_credits(&mut c, 1);
    assert!(spend_credit(&mut c));
    assert!(!spend_credit(&mut c));
}

#[test]
fn a_grant_past_the_ceiling_ends_the_channel_and_leaves_the_count_alone() {
    let mut c = credit_chan();
    assert_eq!(grant_credits(&mut c, u::LE_MAX_CREDITS), Grant::Applied(u::LE_MAX_CREDITS));
    assert_eq!(grant_credits(&mut c, 1), Grant::Overflow);
    assert_eq!(c.tx_credits, u::LE_MAX_CREDITS);
}

#[test]
fn a_grant_that_would_overflow_from_a_partial_count_is_refused() {
    let mut c = credit_chan();
    grant_credits(&mut c, 10);
    assert_eq!(grant_credits(&mut c, u::LE_MAX_CREDITS - 9), Grant::Overflow);
    assert_eq!(c.tx_credits, 10);
    // The largest grant that still fits is accepted.
    assert_eq!(grant_credits(&mut c, u::LE_MAX_CREDITS - 10), Grant::Applied(u::LE_MAX_CREDITS));
}

#[test]
fn a_whole_sdu_in_one_frame_is_delivered_immediately() {
    let mut c = credit_chan();
    c.rx_credits = 4;
    let mut frame = vec![3u8, 0];
    frame.extend_from_slice(&[1, 2, 3]);
    assert_eq!(le_data_recv(&mut c, &frame), LeRecv::Complete(vec![1, 2, 3]));
    assert_eq!(c.rx_credits, 3);
}

#[test]
fn a_segmented_sdu_reassembles_across_frames() {
    let mut c = credit_chan();
    c.rx_credits = 8;
    let sdu: alloc::vec::Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let frames = super::super::sar::segment_le_sdu(&sdu, c.mps).unwrap();
    let mut got = None;
    for f in &frames {
        match le_data_recv(&mut c, f) {
            LeRecv::Complete(v) => got = Some(v),
            LeRecv::Incomplete => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(got, Some(sdu));
}

#[test]
fn a_frame_arriving_with_no_credit_ends_the_channel() {
    let mut c = credit_chan();
    c.rx_credits = 0;
    assert_eq!(le_data_recv(&mut c, &[0, 0]), LeRecv::Disconnect);
}

#[test]
fn a_frame_larger_than_the_agreed_pdu_ends_the_channel() {
    let mut c = credit_chan();
    c.rx_credits = 4;
    c.mps = 8;
    assert_eq!(le_data_recv(&mut c, &[0u8; 9]), LeRecv::Disconnect);
}

#[test]
fn a_declared_sdu_larger_than_the_receive_mtu_ends_the_channel() {
    let mut c = credit_chan();
    c.rx_credits = 4;
    c.imtu = 16;
    c.mps = 16;
    let frame = [0xff, 0x00, 1, 2];
    assert_eq!(le_data_recv(&mut c, &frame), LeRecv::Disconnect);
}

#[test]
fn more_bytes_than_the_sdu_declared_ends_the_channel() {
    let mut c = credit_chan();
    c.rx_credits = 8;
    c.mps = 16;
    let mut first = vec![10u8, 0];
    first.extend_from_slice(&[0; 8]);
    assert_eq!(le_data_recv(&mut c, &first), LeRecv::Incomplete);
    // Five more bytes would take the SDU past the ten it declared.
    assert_eq!(le_data_recv(&mut c, &[0; 5]), LeRecv::Disconnect);
    assert!(c.le_sdu.is_empty());
}

#[test]
fn a_first_frame_too_short_to_hold_its_own_length_is_malformed() {
    let mut c = credit_chan();
    c.rx_credits = 4;
    assert_eq!(le_data_recv(&mut c, &[1]), LeRecv::Malformed);
}

#[test]
fn credits_are_granted_only_while_the_peer_holds_fewer_than_the_buffer_justifies() {
    let mut c = credit_chan();
    c.rx_credits = 0;
    let give = credits_to_grant(&mut c);
    assert!(give > 0);
    assert_eq!(c.rx_credits, give);
    assert_eq!(credits_to_grant(&mut c), 0);
}

#[test]
fn a_known_receive_buffer_bounds_what_is_granted() {
    let mut c = credit_chan();
    c.rx_avail = Some(0);
    c.rx_credits = 0;
    assert_eq!(credits_to_grant(&mut c), 0);
    c.rx_avail = Some(c.mps as usize * 3);
    assert_eq!(credits_to_grant(&mut c), 3);
}

#[test]
fn a_channel_outside_the_credit_modes_grants_nothing() {
    let mut c = credit_chan();
    c.mode = u::MODE_BASIC;
    c.rx_credits = 0;
    assert_eq!(credits_to_grant(&mut c), 0);
}

#[test]
fn the_two_connect_variants_have_different_parameter_floors() {
    assert!(le_conn_params_valid(u::LE_MIN_MTU, u::LE_MIN_MTU));
    assert!(!le_conn_params_valid(u::LE_MIN_MTU - 1, u::LE_MIN_MTU));
    assert!(!le_conn_params_valid(u::LE_MIN_MTU, u::LE_MIN_MTU - 1));
    assert!(ecred_conn_params_valid(u::ECRED_MIN_MTU, u::ECRED_MIN_MPS));
    assert!(!ecred_conn_params_valid(u::ECRED_MIN_MTU - 1, u::ECRED_MIN_MPS));
    assert!(!ecred_conn_params_valid(u::ECRED_MIN_MTU, u::ECRED_MIN_MPS - 1));
}

#[test]
fn a_reconfiguration_may_not_shrink_an_mtu_in_use() {
    assert_eq!(ecred_reconf_verdict(&[(128, 64)], 100, 64), u::RECONF_INVALID_MTU);
    assert_eq!(ecred_reconf_verdict(&[(64, 64)], 128, 64), u::RECONF_SUCCESS);
}

#[test]
fn a_reconfiguration_may_shrink_the_pdu_of_one_channel_but_not_of_several() {
    assert_eq!(ecred_reconf_verdict(&[(64, 128)], 128, 64), u::RECONF_SUCCESS);
    assert_eq!(ecred_reconf_verdict(&[(64, 128), (64, 128)], 128, 64), u::RECONF_INVALID_MPS);
}

#[test]
fn a_reconfiguration_below_the_floors_names_the_parameters() {
    assert_eq!(ecred_reconf_verdict(&[], u::ECRED_MIN_MTU - 1, u::ECRED_MIN_MPS), u::RECONF_INVALID_PARAMS);
    assert_eq!(ecred_reconf_verdict(&[], u::ECRED_MIN_MTU, u::ECRED_MIN_MPS - 1), u::RECONF_INVALID_PARAMS);
    let too_many = [(64u16, 64u16); u::ECRED_MAX_CID + 1];
    assert_eq!(ecred_reconf_verdict(&too_many, 128, 128), u::RECONF_INVALID_PARAMS);
}
