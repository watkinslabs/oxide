// Stream-receive coalescing boundaries for a receive with NO control buffer
// (`read(2)`, `recvfrom(2)`, `recv(2)` without a msghdr).
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

/// Absolute stream offset a control-buffer-less receive must stop at, given
/// the queued segments in ascending offset order. `consumed`/`produced` are
/// the ring's monotonic byte cursors; the answer is never past `produced`.
/// # C: O(segments)
pub fn coalesce_stop<'a>(segments: impl Iterator<Item = Segment<'a>>,
    consumed: u64, produced: u64, passcred: bool) -> u64
{
    // Descriptors on the segment the cursor currently sits inside, and the
    // credential the receive has committed to gluing on.
    let mut current_rights = false;
    let mut first_cred: Option<&MsgCred> = None;
    for seg in segments {
        if seg.off <= consumed {
            current_rights = seg.has_rights;
            first_cred = Some(seg.cred);
            continue;
        }
        if current_rights { return seg.off; }
        if passcred {
            match first_cred {
                Some(first) if !first.same_sender(seg.cred) => return seg.off,
                None => first_cred = Some(seg.cred),
                _ => {}
            }
        }
        current_rights = seg.has_rights;
    }
    produced
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
}
