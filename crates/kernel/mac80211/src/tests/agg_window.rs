// Sequence-number window arithmetic, exhaustively across the wrap.
//
// This is the highest-value target in the layer: an off-by-one here does not
// fail loudly, it stalls a link. Every property below is checked at EVERY
// point of the 4096-value space, not at a handful of samples, because the
// only interesting points are the ones next to the wrap and a sampled test
// walks straight past them.

use crate::agg::window::{sn, sn_add, sn_greater, sn_inc, sn_less, sn_less_eq, sn_sub,
                         Placement, TxWindow, Window, SEQ_MODULO_TEST as MODULO};

/// Half the space; the point at which "behind" becomes "ahead".
const HALF: u16 = MODULO / 2;

#[test]
fn less_is_antisymmetric_everywhere() {
    // For every pair at every distance, exactly one of the two orderings
    // holds unless they are equal or exactly half the space apart — the one
    // distance at which "behind" has no answer.
    for a in 0..MODULO {
        for d in 1..MODULO {
            let b = sn_add(a, d);
            let forward = sn_less(a, b);
            let backward = sn_less(b, a);
            if d == HALF { assert_eq!(forward, backward, "a={a} d={d}"); }
            else { assert_ne!(forward, backward, "a={a} d={d}"); }
        }
    }
}

#[test]
fn less_matches_short_distance_everywhere() {
    // `a` is behind `b` exactly when going forward from a to b is the shorter
    // way round. Checked at every a and every distance.
    for a in 0..MODULO {
        for d in 1..HALF {
            let ahead = sn_add(a, d);
            let behind = sn_sub(a, d);
            assert!(sn_less(a, ahead), "a={a} d={d}");
            assert!(sn_greater(a, behind), "a={a} d={d}");
        }
    }
}

#[test]
fn equal_is_neither_less_nor_greater() {
    for a in 0..MODULO {
        assert!(!sn_less(a, a));
        assert!(!sn_greater(a, a));
        assert!(sn_less_eq(a, a));
    }
}

#[test]
fn increment_wraps_at_the_modulus() {
    for a in 0..MODULO { assert_eq!(sn_inc(a), (a + 1) % MODULO); }
    assert_eq!(sn_inc(MODULO - 1), 0);
    assert_eq!(sn(MODULO), 0);
}

#[test]
fn subtraction_is_the_forward_distance() {
    for a in 0..MODULO {
        for d in 0..MODULO { assert_eq!(sn_sub(sn_add(a, d), a), d, "a={a} d={d}"); }
    }
}

/// Window size used throughout the placement tests. Small enough that every
/// head position can be walked, large enough to have an interior.
const SIZE: u16 = 8;

#[test]
fn frame_at_the_head_is_in_window_at_every_head_position() {
    for head in 0..MODULO {
        let w = Window::new(head, SIZE);
        assert_eq!(w.place(head), Placement::InWindow(0), "head={head}");
    }
}

#[test]
fn frame_at_the_window_edge_is_accepted_not_moved() {
    // The last slot the window covers is INSIDE it. Treating it as ahead
    // would advance the window by one on every in-order burst and drop the
    // frame that was legitimately still coming.
    for head in 0..MODULO {
        let w = Window::new(head, SIZE);
        let edge = sn_add(head, SIZE - 1);
        assert_eq!(w.place(edge), Placement::InWindow((SIZE - 1) as usize),
                   "head={head}");
    }
}

#[test]
fn one_past_the_edge_moves_the_window_by_exactly_one() {
    for head in 0..MODULO {
        let w = Window::new(head, SIZE);
        let past = sn_add(head, SIZE);
        assert_eq!(w.place(past), Placement::Ahead { new_head: sn_inc(head) },
                   "head={head}");
    }
}

#[test]
fn one_below_the_head_is_old_at_every_head_position() {
    for head in 0..MODULO {
        let w = Window::new(head, SIZE);
        assert_eq!(w.place(sn_sub(head, 1)), Placement::Old, "head={head}");
    }
}

#[test]
fn every_interior_offset_reports_its_own_offset() {
    for head in 0..MODULO {
        let w = Window::new(head, SIZE);
        for off in 0..SIZE {
            assert_eq!(w.place(sn_add(head, off)), Placement::InWindow(off as usize),
                       "head={head} off={off}");
        }
    }
}

#[test]
fn a_far_jump_moves_the_window_to_hold_the_frame_last() {
    // A frame far ahead puts itself in the LAST slot, so the window keeps as
    // much of the space behind it as it can rather than skipping past frames
    // still in flight.
    for head in 0..MODULO {
        let w = Window::new(head, SIZE);
        for jump in SIZE..(HALF - 1) {
            let target = sn_add(head, jump);
            match w.place(target) {
                Placement::Ahead { new_head } => {
                    assert_eq!(sn_add(new_head, SIZE - 1), target,
                               "head={head} jump={jump}");
                }
                other => panic!("head={head} jump={jump} placed {other:?}"),
            }
        }
    }
}

#[test]
fn the_wrap_is_crossed_in_both_directions() {
    // A window straddling the wrap: head near the top, tail past zero.
    let head = MODULO - 3;
    let w = Window::new(head, SIZE);
    assert_eq!(w.tail_sn(), sn_add(head, SIZE - 1));
    // Frames on both sides of zero are inside it.
    assert_eq!(w.place(MODULO - 1), Placement::InWindow(2));
    assert_eq!(w.place(0), Placement::InWindow(3));
    assert_eq!(w.place(4), Placement::InWindow(7));
    // One past the tail moves it; one before the head is old.
    assert_eq!(w.place(5), Placement::Ahead { new_head: sn_inc(head) });
    assert_eq!(w.place(MODULO - 4), Placement::Old);
}

#[test]
fn advance_distance_is_measured_forward_across_the_wrap() {
    let w = Window::new(MODULO - 2, SIZE);
    assert_eq!(w.advance_by(2), 4);
    assert_eq!(w.advance_by(MODULO - 2), 0);
}

#[test]
fn transmit_window_holds_at_its_size() {
    let mut w = TxWindow::new(100, 4);
    for i in 0..4 { assert_eq!(w.take(), Some(sn_add(100, i))); }
    assert_eq!(w.outstanding(), 4);
    assert_eq!(w.take(), None, "a full window must not hand out another number");
    assert!(w.ack_upto(102));
    assert_eq!(w.outstanding(), 2);
    assert_eq!(w.take(), Some(104));
}

#[test]
fn transmit_window_refuses_an_acknowledgement_it_never_sent() {
    let mut w = TxWindow::new(0, 8);
    w.take();
    w.take();
    // Beyond what was sent.
    assert!(!w.ack_upto(5));
    // Behind what was already acknowledged.
    assert!(w.ack_upto(2));
    assert!(!w.ack_upto(1));
    assert_eq!(w.start_sn, 2);
}

#[test]
fn transmit_window_wraps() {
    let mut w = TxWindow::new(MODULO - 2, 4);
    assert_eq!(w.take(), Some(MODULO - 2));
    assert_eq!(w.take(), Some(MODULO - 1));
    assert_eq!(w.take(), Some(0));
    assert_eq!(w.outstanding(), 3);
    assert!(w.ack_upto(0));
    assert_eq!(w.outstanding(), 1);
}
