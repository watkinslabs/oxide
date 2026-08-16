// Fragmentation against the threshold.
//
// The threshold covers the WHOLE frame — header and cipher overhead
// included — so splitting the payload to the threshold and then adding the
// header produces fragments over it, which is what makes a fragmentation
// threshold appear not to work.

use crate::limits;
use crate::tx::frag;

const HDR: usize = 26;
const OVERHEAD: usize = 16;

#[test]
fn a_frame_under_the_threshold_is_not_split() {
    let pieces = frag::split(500, HDR, OVERHEAD, 100);
    assert_eq!(pieces.len(), 1);
    assert!(!pieces[0].more);
    assert_eq!((pieces[0].start, pieces[0].end), (0, 100));
    assert!(!frag::needed(500, HDR, OVERHEAD, 100));
}

#[test]
fn the_threshold_is_measured_over_the_whole_frame() {
    // A payload of 100 with 42 bytes of header and cipher is 142 on the air.
    assert!(!frag::needed(142, HDR, OVERHEAD, 100));
    assert!(frag::needed(141, HDR, OVERHEAD, 100),
            "the header and the cipher count toward the threshold");
}

#[test]
fn every_fragment_fits_under_the_threshold() {
    // Payload sizes a real interface produces: anything larger than the
    // link's own maximum cannot arrive here, and the four-bit fragment
    // number is what bounds the count.
    for threshold in [256u32, 300, 512, 1000, 1500] {
        let pieces = frag::split(threshold, HDR, OVERHEAD, 1500);
        for p in pieces.iter() {
            let on_air = HDR + OVERHEAD + (p.end - p.start);
            assert!(on_air as u32 <= threshold,
                    "threshold {threshold}: a fragment of {on_air} went over");
        }
    }
}

#[test]
fn the_pieces_cover_the_payload_exactly_once_and_in_order() {
    let pieces = frag::split(300, HDR, OVERHEAD, 1000);
    assert!(pieces.len() > 1);
    let mut at = 0usize;
    for (i, p) in pieces.iter().enumerate() {
        assert_eq!(p.start, at, "piece {i} does not follow the previous one");
        assert!(p.end > p.start, "piece {i} is empty");
        assert_eq!(p.number, i as u16);
        assert_eq!(p.more, i + 1 < pieces.len());
        at = p.end;
    }
    assert_eq!(at, 1000, "the pieces do not cover the payload");
}

#[test]
fn the_last_piece_is_the_only_one_without_the_more_bit() {
    let pieces = frag::split(400, HDR, OVERHEAD, 2000);
    assert!(pieces.len() >= 2);
    assert!(pieces.iter().rev().skip(1).all(|p| p.more));
    assert!(!pieces.last().unwrap().more);
}

#[test]
fn the_threshold_off_value_splits_nothing() {
    let pieces = frag::split(limits::FRAG_THRESHOLD_OFF, HDR, OVERHEAD, 9000);
    assert_eq!(pieces.len(), 1);
    assert!(!frag::needed(limits::FRAG_THRESHOLD_OFF, HDR, OVERHEAD, 9000));
}

#[test]
fn a_threshold_with_no_room_for_payload_yields_one_piece() {
    // An endless list of empty fragments is worse than a frame over the
    // threshold, so the split gives up rather than looping.
    let pieces = frag::split((HDR + OVERHEAD) as u32, HDR, OVERHEAD, 500);
    assert_eq!(pieces.len(), 1);
    assert_eq!(pieces[0].end, 500);
}

#[test]
fn the_fragment_number_never_exceeds_the_field_width() {
    // The field is four bits wide. A payload needing more pieces than that
    // goes out with one oversized last fragment rather than as pieces the
    // receiver cannot order.
    let pieces = frag::split(300, HDR, OVERHEAD, 100_000);
    assert!(pieces.len() <= limits::MAX_FRAGMENTS);
    assert!(pieces.iter().all(|p| (p.number as usize) < limits::MAX_FRAGMENTS));
    assert_eq!(pieces.last().unwrap().end, 100_000);
    assert!(!pieces.last().unwrap().more);
}

#[test]
fn an_empty_payload_is_a_single_empty_piece() {
    let pieces = frag::split(300, HDR, OVERHEAD, 0);
    assert_eq!(pieces.len(), 1);
    assert_eq!((pieces[0].start, pieces[0].end), (0, 0));
}
