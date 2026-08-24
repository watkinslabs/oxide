//! Frame pacing and the transport state machine.

use crate::device::{due, next_deadline, period_ns, Vivid};
use v4l2::format::Fract;
use v4l2::ops::VideoOps;

const THIRTY: Fract = Fract { numerator: 1, denominator: 30 };
const FIFTEEN: Fract = Fract { numerator: 1, denominator: 15 };

#[test]
fn a_period_is_the_interval_in_nanoseconds() {
    assert_eq!(period_ns(THIRTY), 33_333_333);
    assert_eq!(period_ns(FIFTEEN), 66_666_666);
    assert_eq!(period_ns(Fract { numerator: 2, denominator: 30 }), 66_666_666);
    // A meaningless interval falls back rather than dividing by zero.
    assert_eq!(period_ns(Fract { numerator: 1, denominator: 0 }), 1_000_000_000 / 30);
    assert_eq!(period_ns(Fract { numerator: 0, denominator: 30 }), 1_000_000_000 / 30);
}

#[test]
fn the_first_frame_of_a_stream_is_due_immediately() {
    let period = period_ns(THIRTY);
    // A program that starts a stream and waits must not sit out a whole period
    // before its first frame.
    assert!(due(0, 0, period));
    assert!(!due(1_000, 1_000, period));
    assert!(!due(1_000, 1_000 + period - 1, period));
    assert!(due(1_000, 1_000 + period, period));
    assert!(due(1_000, 1_000 + period * 5, period));
}

#[test]
fn pacing_advances_by_whole_periods_so_the_rate_does_not_drift() {
    let period = period_ns(THIRTY);
    let start = 1_000_000u64;
    // A tick that arrives a little late books the frame against its nominal
    // slot, not against the tick.
    let late = start + period + 5_000;
    assert_eq!(next_deadline(start, late, period), start + period);
    // Two periods behind catches up two slots at once.
    assert_eq!(next_deadline(start, start + period * 2 + 10, period), start + period * 2);
    // A gap of more than a second is not pacing; it resynchronises rather than
    // producing a burst of catch-up frames.
    let stall = start + 3_000_000_000;
    assert_eq!(next_deadline(start, stall, period), stall);
    // The first frame books against now.
    assert_eq!(next_deadline(0, 12_345, period), 12_345);
}

#[test]
fn nothing_is_produced_before_streaming_starts() {
    let vivid = Vivid::new();
    assert!(!vivid.streaming());
    assert!(vivid.take_due(1_000_000).is_none());
    vivid.buf_queue(0);
    assert!(vivid.take_due(1_000_000).is_none(),
            "a buffer queued while stopped must not be filled");
}

#[test]
fn frames_come_out_in_order_with_a_rising_sequence() {
    let vivid = Vivid::new();
    vivid.set_interval(THIRTY);
    vivid.start_streaming(&[0, 1, 2]).expect("start");
    assert!(vivid.streaming());
    let period = vivid.frame_period_ns();
    let first = vivid.take_due(1_000_000).expect("the first frame is due at once");
    assert_eq!((first.index, first.sequence), (0, 1));
    assert!(!first.error);
    // Not yet due.
    assert!(vivid.take_due(1_000_000 + period / 2).is_none());
    let second = vivid.take_due(1_000_000 + period).expect("the next period");
    assert_eq!((second.index, second.sequence), (1, 2));
    let third = vivid.take_due(1_000_000 + period * 2).expect("and the next");
    assert_eq!((third.index, third.sequence), (2, 3));
    // The pool is empty; nothing more comes out until a buffer is requeued.
    assert!(vivid.take_due(1_000_000 + period * 3).is_none());
    vivid.buf_queue(1);
    let fourth = vivid.take_due(1_000_000 + period * 4).expect("the requeued buffer");
    assert_eq!((fourth.index, fourth.sequence), (1, 4));
}

#[test]
fn dqbuf_error_button_marks_only_the_next_frame() {
    let vivid = Vivid::new();
    vivid.start_streaming(&[0, 1]).expect("start");
    vivid.control_changed(crate::tables::CID_DQBUF_ERROR, 0);
    let first = vivid.take_due(1_000).expect("first frame");
        assert!(first.error, "the button must reach the next completion");
        vivid.buf_queue(0);
    let next = 1_000 + vivid.frame_period_ns();
    let second = vivid.take_due(next).expect("requeued frame");
    assert!(!second.error, "the reference consumes the injection once");
}

#[test]
fn stopping_drops_the_buffers_the_transport_was_holding() {
    let vivid = Vivid::new();
    vivid.start_streaming(&[0, 1, 2]).expect("start");
    vivid.stop_streaming();
    assert!(!vivid.streaming());
    // The core returns these buffers to the caller, so filling one afterwards
    // would write into memory the application already owns again.
    assert!(vivid.take_due(u64::MAX / 2).is_none());
    vivid.start_streaming(&[3]).expect("restart");
    let frame = vivid.take_due(1_000).expect("the restarted stream produces");
    assert_eq!(frame.index, 3);
    assert_eq!(frame.sequence, 1, "a restarted stream counts from one again");
}

#[test]
fn the_selected_interval_is_what_paces_the_stream() {
    let vivid = Vivid::new();
    vivid.set_interval(FIFTEEN);
    assert_eq!(vivid.frame_period_ns(), period_ns(FIFTEEN));
    vivid.start_streaming(&[0, 1]).expect("start");
    let base = 5_000_000u64;
    vivid.take_due(base).expect("the first frame");
    // A thirtieth of a second is not enough at fifteen frames a second.
    assert!(vivid.take_due(base + period_ns(THIRTY)).is_none());
    assert!(vivid.take_due(base + period_ns(FIFTEEN)).is_some());
}

#[test]
fn every_declared_interval_produces_a_usable_period() {
    for interval in crate::tables::INTERVALS {
        let period = period_ns(*interval);
        assert!(period > 0, "{interval:?} paces nothing");
        assert!(period <= 1_000_000_000, "{interval:?} is slower than one frame a second");
    }
}
