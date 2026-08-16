// The reorder buffer: what comes out, in what order, and when.

use alloc::vec;
use alloc::vec::Vec;

use crate::agg::tid_rx::{ReorderBuf, RxAgg};
use crate::agg::window::sn_add;
use crate::limits;

fn frame(n: u8) -> Vec<u8> { vec![n; 4] }

fn released(r: RxAgg) -> Vec<u8> {
    match r {
        RxAgg::Released(v) => v.into_iter().map(|f| f[0]).collect(),
        RxAgg::Dropped => Vec::new(),
    }
}

fn is_dropped(r: &RxAgg) -> bool { matches!(r, RxAgg::Dropped) }

#[test]
fn in_order_frames_pass_straight_through() {
    let mut b = ReorderBuf::new(0, 8, 0);
    for n in 0..8u8 {
        assert_eq!(released(b.receive(n as u16, frame(n), 0)), vec![n]);
    }
    assert_eq!(b.stored, 0);
}

#[test]
fn an_out_of_order_frame_waits_for_the_gap_to_fill() {
    let mut b = ReorderBuf::new(0, 8, 0);
    // 1 and 2 arrive before 0: nothing may be released, because 0 is still
    // legitimately in flight.
    assert_eq!(released(b.receive(1, frame(1), 0)), Vec::<u8>::new());
    assert_eq!(released(b.receive(2, frame(2), 0)), Vec::<u8>::new());
    assert_eq!(b.stored, 2);
    // 0 arrives and all three come out in order.
    assert_eq!(released(b.receive(0, frame(0), 0)), vec![0, 1, 2]);
    assert_eq!(b.stored, 0);
}

#[test]
fn a_second_copy_of_a_held_frame_is_dropped() {
    let mut b = ReorderBuf::new(0, 8, 0);
    b.receive(3, frame(3), 0);
    assert!(is_dropped(&b.receive(3, frame(9), 0)),
            "a frame already held must not be replaced");
    assert_eq!(b.stored, 1);
    assert_eq!(released(b.receive(0, frame(0), 0)), vec![0]);
}

#[test]
fn a_frame_behind_the_window_is_dropped() {
    let mut b = ReorderBuf::new(10, 8, 0);
    assert!(is_dropped(&b.receive(9, frame(9), 0)));
    assert!(is_dropped(&b.receive(0, frame(0), 0)));
}

#[test]
fn a_frame_past_the_window_moves_it_and_releases_what_it_passed() {
    let mut b = ReorderBuf::new(0, 4, 0);
    b.receive(1, frame(1), 0);
    b.receive(2, frame(2), 0);
    // 4 is one past the window (0..3). The window advances by one, giving up
    // on 0 and releasing 1 and 2 which were behind it, then 4 sits at the end.
    let out = released(b.receive(4, frame(4), 0));
    assert_eq!(out, vec![1, 2], "the abandoned hole releases what was behind it");
    assert_eq!(b.win.head_sn, 3);
    assert_eq!(released(b.receive(3, frame(3), 0)), vec![3, 4]);
}

#[test]
fn the_release_timeout_gives_up_on_a_hole() {
    let mut b = ReorderBuf::new(0, 8, 0);
    b.receive(1, frame(1), 0);
    b.receive(2, frame(2), 0);
    // Before the timeout nothing moves: 0 may still arrive.
    assert!(b.release_timed_out(limits::REORDER_RELEASE_NS - 1).is_empty());
    let out: Vec<u8> = b.release_timed_out(limits::REORDER_RELEASE_NS)
        .into_iter().map(|f| f[0]).collect();
    assert_eq!(out, vec![1, 2]);
    assert_eq!(b.win.head_sn, 3);
}

#[test]
fn a_buffer_with_no_hole_needs_no_timeout() {
    let mut b = ReorderBuf::new(0, 8, 0);
    b.receive(0, frame(0), 0);
    assert!(b.release_timed_out(u64::MAX).is_empty());
}

#[test]
fn reordering_works_across_the_sequence_wrap() {
    let start = 4090u16;
    let mut b = ReorderBuf::new(start, 8, 0);
    // Arrive out of order across zero.
    let order = [2u16, 4095, 0, 4094, 1, 4093, 4092, 4091, 4090];
    for s in order { b.receive(s, vec![(s & 0xff) as u8], 0); }
    // Everything is contiguous now, so the whole run came out in order.
    assert_eq!(b.stored, 0);
    assert_eq!(b.win.head_sn, sn_add(start, 9));
}

#[test]
fn a_block_ack_request_releases_what_is_behind_it() {
    let mut b = ReorderBuf::new(0, 8, 0);
    b.receive(2, frame(2), 0);
    b.receive(3, frame(3), 0);
    let out: Vec<u8> = b.bar(2).into_iter().map(|f| f[0]).collect();
    assert_eq!(out, vec![2, 3]);
    assert_eq!(b.win.head_sn, 4);
}

#[test]
fn a_block_ack_request_behind_the_head_moves_nothing() {
    let mut b = ReorderBuf::new(10, 8, 0);
    b.receive(11, frame(1), 0);
    assert!(b.bar(9).is_empty());
    assert_eq!(b.win.head_sn, 10);
}

#[test]
fn flush_releases_everything_in_order() {
    let mut b = ReorderBuf::new(0, 8, 0);
    b.receive(5, frame(5), 0);
    b.receive(1, frame(1), 0);
    b.receive(7, frame(7), 0);
    let out: Vec<u8> = b.flush().into_iter().map(|f| f[0]).collect();
    assert_eq!(out, vec![1, 5, 7]);
    assert_eq!(b.stored, 0);
}

#[test]
fn a_zero_buffer_size_is_clamped_to_something_usable() {
    // A peer asking for no buffer must not produce a buffer that can never
    // release anything.
    let b = ReorderBuf::new(0, 0, 0);
    assert!(b.size() >= limits::MIN_AGG_BUF_SIZE);
}

#[test]
fn an_idle_session_is_reported_idle_only_after_its_own_timeout() {
    let mut b = ReorderBuf::new(0, 8, 0);
    b.timeout_tu = 100;
    let limit = limits::tu_to_ns(100);
    assert!(!b.is_idle(limit - 1));
    assert!(b.is_idle(limit));
    b.receive(0, frame(0), limit);
    assert!(!b.is_idle(limit + 1));
}
