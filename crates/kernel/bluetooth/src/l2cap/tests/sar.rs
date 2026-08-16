//! Segmentation and reassembly: an SDU larger than one PDU comes back byte for
//! byte, and every sequence that cannot produce an SDU is refused.

use super::*;
use alloc::vec;

fn chan_with_imtu(imtu: u16) -> Channel {
    let mut c = Channel::new();
    c.imtu = imtu;
    c
}

fn feed(chan: &mut Channel, segs: &[Segment]) -> Option<alloc::vec::Vec<u8>> {
    let mut done = None;
    for s in segs {
        match reassemble(chan, s.sar, &s.wire()) {
            Reassembly::Complete(v) => done = Some(v),
            Reassembly::Incomplete => {}
            Reassembly::Error => return None,
        }
    }
    done
}

#[test]
fn an_sdu_that_fits_one_pdu_is_sent_unsegmented() {
    let segs = segment_sdu(&[1, 2, 3], 10).unwrap();
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0].sar, u::SAR_UNSEGMENTED);
    assert_eq!(segs[0].sdu_len, None);
    assert_eq!(segs[0].wire(), vec![1, 2, 3]);
}

#[test]
fn an_sdu_larger_than_one_pdu_reassembles_to_the_original_bytes() {
    let sdu: alloc::vec::Vec<u8> = (0..250u32).map(|i| i as u8).collect();
    let segs = segment_sdu(&sdu, 64).unwrap();
    assert_eq!(segs[0].sar, u::SAR_START);
    assert_eq!(segs[0].sdu_len, Some(250));
    assert_eq!(segs[segs.len() - 1].sar, u::SAR_END);
    for s in &segs[1..segs.len() - 1] { assert_eq!(s.sar, u::SAR_CONTINUE); }
    let mut chan = chan_with_imtu(1000);
    assert_eq!(feed(&mut chan, &segs), Some(sdu));
}

#[test]
fn every_segment_stays_within_the_payload_bound() {
    let sdu: alloc::vec::Vec<u8> = (0..500u32).map(|i| i as u8).collect();
    for s in segment_sdu(&sdu, 48).unwrap() { assert!(s.payload.len() <= 48); }
}

#[test]
fn a_continuation_with_no_start_is_refused() {
    let mut chan = chan_with_imtu(1000);
    assert_eq!(reassemble(&mut chan, u::SAR_CONTINUE, &[1, 2]), Reassembly::Error);
}

#[test]
fn a_second_start_on_top_of_one_in_progress_is_refused() {
    let sdu: alloc::vec::Vec<u8> = (0..100u32).map(|i| i as u8).collect();
    let segs = segment_sdu(&sdu, 32).unwrap();
    let mut chan = chan_with_imtu(1000);
    assert_eq!(reassemble(&mut chan, segs[0].sar, &segs[0].wire()), Reassembly::Incomplete);
    assert_eq!(reassemble(&mut chan, segs[0].sar, &segs[0].wire()), Reassembly::Error);
}

#[test]
fn a_declared_length_over_the_receive_mtu_is_refused() {
    let sdu: alloc::vec::Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let segs = segment_sdu(&sdu, 32).unwrap();
    let mut chan = chan_with_imtu(100);
    assert_eq!(reassemble(&mut chan, segs[0].sar, &segs[0].wire()), Reassembly::Error);
}

#[test]
fn an_end_whose_total_disagrees_with_the_declaration_is_refused() {
    let sdu: alloc::vec::Vec<u8> = (0..100u32).map(|i| i as u8).collect();
    let mut segs = segment_sdu(&sdu, 32).unwrap();
    let last = segs.len() - 1;
    segs[last].payload.pop();
    let mut chan = chan_with_imtu(1000);
    assert_eq!(feed(&mut chan, &segs), None);
    assert!(chan.ertm.sdu.is_empty());
}

#[test]
fn a_start_shorter_than_its_own_length_prefix_is_refused() {
    let mut chan = chan_with_imtu(1000);
    assert_eq!(reassemble(&mut chan, u::SAR_START, &[7]), Reassembly::Error);
}

#[test]
fn the_payload_bound_falls_out_of_the_link_and_the_peer_limit() {
    // The peer's declared limit binds when it is the smaller of the two.
    assert_eq!(ertm_pdu_len(1021, u::FCS_CRC16, false, 100), Some(100));
    // Otherwise the link's packet size less the framing does.
    let n = ertm_pdu_len(200, u::FCS_CRC16, false, 4096).unwrap();
    assert_eq!(n, 200 - u::FCS_SIZE - u::ENH_HDR_SIZE);
    // The extended control field costs two more bytes.
    assert_eq!(ertm_pdu_len(200, u::FCS_NONE, true, 4096), Some(200 - u::EXT_HDR_SIZE));
    // A bound leaving no room is an unusable channel, not a zero-length PDU.
    assert_eq!(ertm_pdu_len(4, u::FCS_CRC16, true, 4096), None);
    assert_eq!(ertm_pdu_len(1021, u::FCS_NONE, false, 0), None);
}

#[test]
fn credit_mode_frames_fill_the_pdu_after_the_first_pays_for_the_prefix() {
    let sdu: alloc::vec::Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let frames = segment_le_sdu(&sdu, 64).unwrap();
    assert_eq!(frames[0].len(), 64);
    assert_eq!(u16::from_le_bytes([frames[0][0], frames[0][1]]), 300);
    for f in &frames[1..frames.len() - 1] { assert_eq!(f.len(), 64); }
    let total: usize = frames.iter().map(|f| f.len()).sum();
    assert_eq!(total, sdu.len() + u::SDULEN_SIZE);
}

#[test]
fn a_credit_mode_pdu_too_small_to_hold_the_prefix_cannot_carry_an_sdu() {
    assert!(segment_le_sdu(&[1, 2, 3], 2).is_none());
    assert!(segment_le_sdu(&[1, 2, 3], 1).is_none());
}

#[test]
fn a_zero_length_credit_mode_sdu_still_carries_its_prefix() {
    let frames = segment_le_sdu(&[], 64).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0], vec![0, 0]);
}
