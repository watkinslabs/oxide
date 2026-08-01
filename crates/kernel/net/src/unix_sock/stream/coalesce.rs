// Stream-receive coalescing boundaries. ONE owner for every AF_UNIX stream
// receive: `read(2)`/`recvfrom(2)` without a control buffer AND `recvmsg(2)`
// with one. Both walk the same queued segments and stop at the same offsets;
// only what they can REPORT about the ancillary data differs.
//
// A byte-stream receive walks the queued segments and keeps taking bytes, but
// two things end the walk:
//
// - a segment carrying SCM_RIGHTS ends it AFTER that segment's bytes: the
//   descriptors are discarded (no control buffer took them), yet the receive
//   still stops there rather than gluing the next segment on;
// - when the receiving socket may pass credentials, a segment stamped by a
//   different sender ends it BEFORE that segment's bytes — different writers
//   are never glued into one receive.
//
// Neither stop depends on the receiver offering a control buffer, so a plain
// `read(2)` observes exactly the same boundaries a `recvmsg(2)` would; it
// simply cannot see the ancillary data that produced them. With credential
// passing off, the sender's identity is not a boundary at all.
//
// Ungated on purpose: this is the decision logic, and a target-gated module
// would compile its tests away silently.

use crate::unix_sock::MsgCred;

/// One queued segment as the coalescing rule sees it: the absolute stream
/// offset of its first byte, whether it still carries descriptors, and the
/// credential stamped on it.
#[derive(Clone, Copy)]
pub struct Segment<'a> {
    pub off: u64,
    pub has_rights: bool,
    pub cred: &'a MsgCred,
}

/// Why one receive's run of glued segments ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StopCause {
    /// Nothing more is queued; a later write may still extend this run.
    Drained,
    /// The run ended after a descriptor-bearing segment.
    Rights,
    /// The run ended before a segment stamped by a different writer.
    Sender,
}

/// One receive's run of glued segments. Which segments it reported ancillary
/// data from is [`report_window`]'s answer, not the run's: a receive reports
/// only the segments its copied bytes actually reached.
pub struct Run {
    /// Absolute stream offset the receive must stop at; never past `produced`.
    pub stop: u64,
    pub cause: StopCause,
}

/// The run a receive positioned at `cursor` may glue, given the queued segments
/// in ascending offset order. `cursor`/`produced` are the ring's monotonic byte
/// cursors (`cursor` is past the ring's `consumed` for a MSG_PEEK continuation).
/// `passcred` is whether the RECEIVING socket may pass credentials, which is
/// the only condition under which a writer change is a boundary at all.
/// # C: O(segments)
pub fn coalesce_run<'a>(segments: impl Iterator<Item = Segment<'a>>,
    cursor: u64, produced: u64, passcred: bool) -> Run
{
    // Descriptors on the segment the cursor currently sits inside, and the
    // credential the receive has committed to gluing on.
    let mut current_rights = false;
    let mut first_cred: Option<&MsgCred> = None;
    for seg in segments {
        if seg.off <= cursor {
            current_rights = seg.has_rights;
            first_cred = Some(seg.cred);
            continue;
        }
        if current_rights { return Run { stop: seg.off, cause: StopCause::Rights }; }
        if passcred {
            match first_cred {
                Some(prev) if !prev.same_sender(seg.cred) =>
                    return Run { stop: seg.off, cause: StopCause::Sender },
                None => first_cred = Some(seg.cred),
                _ => {}
            }
        }
        current_rights = seg.has_rights;
    }
    Run { stop: produced, cause: StopCause::Drained }
}

/// Absolute stream offset a receive must stop at. # C: O(segments)
pub fn coalesce_stop<'a>(segments: impl Iterator<Item = Segment<'a>>,
    consumed: u64, produced: u64, passcred: bool) -> u64
{ coalesce_run(segments, consumed, produced, passcred).stop }

/// `(start, count)` of the segments a receive reaching absolute offset
/// `reached` reports ancillary data from: every segment whose first byte is
/// before `reached`. The credential belongs to the FIRST of them (a receive
/// reports the writer it committed to, not the last one glued on) and the
/// descriptors to all of them — which the run rule caps at one bearer, since
/// the segment after a descriptor-bearing one ends the run.
///
/// `reported_through` is set for a MSG_PEEK continuation: the earlier step
/// already reported every segment starting at or before the ring's `consumed`,
/// and a descriptor is never reported twice inside one receive.
/// # C: O(segments)
pub fn report_window<'a>(segments: impl Iterator<Item = Segment<'a>>,
    reached: u64, reported_through: Option<u64>) -> (usize, usize)
{
    let mut start = 0usize;
    let mut count = 0usize;
    for (index, seg) in segments.enumerate() {
        if seg.off >= reached { break; }
        if let Some(through) = reported_through { if seg.off <= through { continue; } }
        if count == 0 { start = index; }
        count += 1;
    }
    (start, count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn cred(pid: u32) -> MsgCred { MsgCred::from_ids((pid, 0, 0)) }

    fn segs<'a>(items: Vec<(u64, bool, &'a MsgCred)>) -> Vec<Segment<'a>> {
        items.into_iter().map(|(off, has_rights, cred)| Segment { off, has_rights, cred }).collect()
    }

    #[test]
    fn equal_senders_without_rights_coalesce_to_the_whole_ring() {
        let a = cred(7);
        let s = segs(alloc::vec![(0, false, &a), (5, false, &a), (11, false, &a)]);
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 20, true), 20);
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 20, false), 20);
    }

    #[test]
    fn a_rights_bearing_segment_stops_the_receive_after_its_bytes() {
        let a = cred(7);
        let s = segs(alloc::vec![(0, true, &a), (5, false, &a)]);
        // The descriptors are dropped, but the next segment is not glued on.
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 20, false), 5);
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 20, true), 5);
    }

    #[test]
    fn rights_on_the_last_segment_do_not_shorten_the_receive() {
        let a = cred(7);
        let s = segs(alloc::vec![(0, false, &a), (5, true, &a)]);
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 20, false), 20);
    }

    #[test]
    fn a_different_sender_stops_the_receive_before_its_bytes_only_with_passcred() {
        let a = cred(7);
        let b = cred(9);
        let s = segs(alloc::vec![(0, false, &a), (5, false, &b)]);
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 20, true), 5);
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 20, false), 20,
            "credential passing off: the sender's identity is not a boundary");
    }

    #[test]
    fn the_sender_boundary_is_measured_against_the_first_glued_segment() {
        let a = cred(7);
        let b = cred(9);
        // a, a, b: the walk commits to `a` and stops where `b` begins.
        let s = segs(alloc::vec![(0, false, &a), (4, false, &a), (8, false, &b), (12, false, &a)]);
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 16, true), 8);
    }

    #[test]
    fn a_cursor_inside_a_segment_keeps_that_segments_attributes() {
        let a = cred(7);
        let b = cred(9);
        let s = segs(alloc::vec![(0, true, &a), (5, false, &b)]);
        // Cursor at 2: still inside the rights-bearing segment, so the stop is
        // its end, not the ring end.
        assert_eq!(coalesce_stop(s.iter().copied(), 2, 20, false), 5);
        // Resuming exactly at the boundary glues from `b` onward.
        assert_eq!(coalesce_stop(s.iter().copied(), 5, 20, true), 20);
    }

    #[test]
    fn a_uid_or_gid_change_is_a_different_writer() {
        let a = MsgCred::from_ids((7, 1000, 1000));
        let same = MsgCred::from_ids((7, 1000, 1000));
        let other_uid = MsgCred::from_ids((7, 1001, 1000));
        let other_gid = MsgCred::from_ids((7, 1000, 1001));
        assert!(a.same_sender(&same));
        assert!(!a.same_sender(&other_uid));
        assert!(!a.same_sender(&other_gid));
        let s = segs(alloc::vec![(0, false, &a), (5, false, &other_uid)]);
        assert_eq!(coalesce_stop(s.iter().copied(), 0, 20, true), 5);
    }

    #[test]
    fn an_empty_segment_list_permits_the_whole_ring() {
        let empty: Vec<Segment<'_>> = Vec::new();
        assert_eq!(coalesce_stop(empty.into_iter(), 3, 9, true), 9);
    }

    #[test]
    fn a_drained_queue_glues_every_segment_into_one_run() {
        let a = cred(7);
        let s = segs(alloc::vec![(0, false, &a), (5, false, &a), (11, false, &a)]);
        let run = coalesce_run(s.iter().copied(), 0, 20, true);
        assert_eq!(run.stop, 20);
        assert_eq!(run.cause, StopCause::Drained);
        assert_eq!(report_window(s.iter().copied(), run.stop, None), (0, 3));
    }

    #[test]
    fn the_rights_bearing_segment_is_the_last_one_in_its_run() {
        let a = cred(7);
        // Two plain segments then a descriptor-bearing one: all three are glued
        // into one receive and the descriptors ride it, but the fourth does not.
        let s = segs(alloc::vec![(0, false, &a), (4, false, &a), (8, true, &a), (12, false, &a)]);
        let run = coalesce_run(s.iter().copied(), 0, 16, true);
        assert_eq!(run.stop, 12);
        assert_eq!(run.cause, StopCause::Rights);
        assert_eq!(report_window(s.iter().copied(), run.stop, None), (0, 3),
            "the descriptors ride the receive that covers their own bytes");
    }

    #[test]
    fn a_sender_change_ends_the_run_before_its_bytes() {
        let a = cred(7);
        let b = cred(9);
        let s = segs(alloc::vec![(0, false, &a), (4, false, &a), (8, false, &b)]);
        let run = coalesce_run(s.iter().copied(), 0, 12, true);
        assert_eq!(run.stop, 8);
        assert_eq!(run.cause, StopCause::Sender);
        assert_eq!(report_window(s.iter().copied(), run.stop, None), (0, 2));
        // Same queue, credential passing off: no boundary at all.
        let run = coalesce_run(s.iter().copied(), 0, 12, false);
        assert_eq!(run.stop, 12);
        assert_eq!(run.cause, StopCause::Drained);
    }

    #[test]
    fn a_run_starting_mid_segment_still_covers_that_segment() {
        let a = cred(7);
        let s = segs(alloc::vec![(0, false, &a), (5, true, &a), (9, false, &a)]);
        let run = coalesce_run(s.iter().copied(), 2, 14, false);
        assert_eq!(run.stop, 9);
        assert_eq!(run.cause, StopCause::Rights);
        assert_eq!(report_window(s.iter().copied(), run.stop, None), (0, 2));
    }

    #[test]
    fn an_exhausted_queue_yields_an_empty_run() {
        let none: Vec<Segment<'_>> = Vec::new();
        let run = coalesce_run(none.iter().copied(), 4, 4, true);
        assert_eq!(run.stop, 4);
        assert_eq!(run.cause, StopCause::Drained);
        assert_eq!(report_window(none.iter().copied(), 4, None), (0, 0));
    }

    #[test]
    fn the_report_window_covers_every_segment_the_bytes_reached() {
        let a = cred(7);
        let s = segs(alloc::vec![(0, false, &a), (4, false, &a), (8, true, &a)]);
        assert_eq!(report_window(s.iter().copied(), 12, None), (0, 3));
        assert_eq!(report_window(s.iter().copied(), 8, None), (0, 2),
            "a segment whose first byte was not reached reports nothing");
        assert_eq!(report_window(s.iter().copied(), 0, None), (0, 0));
    }

    #[test]
    fn a_peek_continuation_does_not_report_a_segment_twice() {
        let a = cred(7);
        let s = segs(alloc::vec![(0, true, &a), (4, false, &a), (8, false, &a)]);
        // The first peek step reported the segment at 0; a continuation whose
        // bytes reach 12 reports only what starts after it.
        assert_eq!(report_window(s.iter().copied(), 12, Some(0)), (1, 2));
    }
}
