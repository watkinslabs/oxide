// Bundled send/receive: the run a transfer maps, the run it consumed, and what
// the completion says about both.

use alloc::vec::Vec;

use super::*;
use crate::io_uring_abi::ops::{IORING_CQE_BUFFER_SHIFT, IORING_CQE_F_BUFFER,
                               IORING_CQE_F_BUF_MORE, IORING_OP_READ, IORING_OP_RECV,
                               IORING_OP_RECVMSG, IORING_OP_SEND, IORING_OP_SENDMSG,
                               IOSQE_BUFFER_SELECT, IOSQE_FIXED_FILE};

fn e(addr: u64, len: u32, bid: u16) -> BufEntry { BufEntry { addr, len, bid } }

fn run(entries: &[BufEntry], max_len: u64, inc: bool) -> (Plan, Vec<Seg>) {
    let mut segs = Vec::new();
    let p = plan(entries, max_len, inc, &mut segs).expect("plan");
    (p, segs)
}

/// A bundle governs an entry only when all three conditions hold at once. The
/// bit alone changes nothing: without a group there is no run to draw from,
/// and on an opcode that reads `ioprio` as a priority the bit is part of a
/// priority value, not a request.
#[test]
fn a_bundle_needs_the_bit_a_group_and_a_bundling_opcode() {
    assert!(effective(IORING_OP_RECV, IOSQE_BUFFER_SELECT, IORING_RECVSEND_BUNDLE));
    assert!(effective(IORING_OP_SEND, IOSQE_BUFFER_SELECT, IORING_RECVSEND_BUNDLE));
    // No group named: an ordinary single-buffer transfer, not a refusal.
    assert!(!effective(IORING_OP_RECV, IOSQE_FIXED_FILE, IORING_RECVSEND_BUNDLE));
    // The bit unset.
    assert!(!effective(IORING_OP_RECV, IOSQE_BUFFER_SELECT, 0));
    // An opcode whose `ioprio` is a priority.
    assert!(!effective(IORING_OP_READ, IOSQE_BUFFER_SELECT, IORING_RECVSEND_BUNDLE));
}

/// A message-carrying send or receive describes its own scatter list, so a run
/// of provided buffers has no place to land: the entry is malformed, not
/// merely inert. Every other opcode is admitted — the bit means nothing there
/// and refusing it would reject a legal priority value.
#[test]
fn a_bundle_on_a_message_opcode_is_refused_and_nothing_else_is() {
    assert_eq!(admit(IORING_OP_SENDMSG, IORING_RECVSEND_BUNDLE), Err(Errno::Einval));
    assert_eq!(admit(IORING_OP_RECVMSG, IORING_RECVSEND_BUNDLE), Err(Errno::Einval));
    assert_eq!(admit(IORING_OP_SEND, IORING_RECVSEND_BUNDLE), Ok(()));
    assert_eq!(admit(IORING_OP_RECV, IORING_RECVSEND_BUNDLE), Ok(()));
    assert_eq!(admit(IORING_OP_READ, IORING_RECVSEND_BUNDLE), Ok(()));
    // Without the bit a message opcode is untouched.
    assert_eq!(admit(IORING_OP_SENDMSG, 0), Ok(()));
    // A priority whose bit 4 happens to be set on a message opcode IS the
    // bundle request, because that is what the field means there.
    assert_eq!(admit(IORING_OP_RECVMSG, IORING_RECVSEND_BUNDLE | 1), Err(Errno::Einval));
}

/// The defining behaviour: one operation maps a RUN of buffers, and the
/// completion names only the first — the caller walks forward from it.
#[test]
fn a_bundle_maps_several_buffers_and_reports_the_first_id() {
    let ents = [e(0x1000, 64, 7), e(0x2000, 64, 8), e(0x3000, 64, 9)];
    let (p, segs) = run(&ents, 0, false);
    assert_eq!(segs.len(), 3);
    assert_eq!(p.total, 192);
    assert_eq!(p.first_bid, 7);
    assert!(!p.partial_map);
    assert_eq!(segs[0], Seg { addr: 0x1000, len: 64 });
    assert_eq!(segs[2], Seg { addr: 0x3000, len: 64 });
    assert_eq!(cqe_flags(p.first_bid, false),
               IORING_CQE_F_BUFFER | (7u32 << IORING_CQE_BUFFER_SHIFT));
}

/// An empty group has no run to map at all.
#[test]
fn an_empty_group_is_enobufs() {
    let mut segs = Vec::new();
    assert_eq!(plan(&[], 128, false, &mut segs), Err(Errno::Enobufs));
    // So is a published entry of zero length, when a length was asked for:
    // dividing the request by it would say the run is unbounded.
    assert_eq!(plan(&[e(0x1000, 0, 3)], 128, false, &mut segs), Err(Errno::Enobufs));
}

/// The run stops at the entry's own length, and stops mid-buffer only when the
/// cap lands there.
#[test]
fn the_run_stops_where_the_requested_length_lands() {
    let ents = [e(0x1000, 64, 0), e(0x2000, 64, 1), e(0x3000, 64, 2), e(0x4000, 64, 3)];
    // Exactly two buffers.
    let (p, segs) = run(&ents, 128, false);
    assert_eq!(segs.len(), 2);
    assert_eq!(p.total, 128);
    assert!(!p.partial_map);
    // One and a half: the second buffer would be cut, so on an ordinary group
    // it is dropped rather than half-consumed.
    let (p, segs) = run(&ents, 96, false);
    assert_eq!(segs.len(), 1);
    assert_eq!(p.total, 64);
    assert!(p.partial_map);
}

/// The FIRST buffer is mapped short rather than dropped: a bundle that maps
/// nothing has no completion to report, and the caller asked for that length.
#[test]
fn a_cap_inside_the_first_buffer_still_maps_it() {
    let ents = [e(0x1000, 64, 5), e(0x2000, 64, 6)];
    let (p, segs) = run(&ents, 16, false);
    assert_eq!(segs, [Seg { addr: 0x1000, len: 16 }]);
    assert_eq!(p.total, 16);
    assert_eq!(p.first_bid, 5);
    assert!(p.partial_map);
}

/// An incremental group keeps the remainder instead of losing it, so a cut
/// buffer is mapped short and is NOT a partial map.
#[test]
fn an_incremental_group_maps_the_cut_buffer_short() {
    let ents = [e(0x1000, 64, 0), e(0x2000, 64, 1)];
    let (p, segs) = run(&ents, 96, true);
    assert_eq!(segs, [Seg { addr: 0x1000, len: 64 }, Seg { addr: 0x2000, len: 32 }]);
    assert_eq!(p.total, 96);
    assert!(!p.partial_map);
}

/// One transfer never maps more than the segment ceiling, whatever the ring
/// holds and whatever length the entry names.
#[test]
fn the_mapped_run_is_bounded() {
    let ents: Vec<BufEntry> = (0..600u16).map(|i| e(0x1000 + i as u64 * 0x10, 1, i)).collect();
    let (_, segs) = run(&ents, 100_000, false);
    assert_eq!(segs.len(), PEEK_MAX_IMPORT);
    // With no length named the run is bounded by what is published.
    let (_, segs) = run(&ents[..8], 0, false);
    assert_eq!(segs.len(), 8);
    // And the window a caller may look at never exceeds the message limit.
    assert_eq!(peek_window(u32::MAX), UIO_MAXIOV);
    assert_eq!(peek_window(3), 3);
}

/// Which buffers the transfer CONSUMED is a separate question from which it
/// mapped: a short transfer hands the untouched tail of the run back.
#[test]
fn only_the_buffers_the_transfer_reached_are_consumed() {
    let segs = [Seg { addr: 0x1000, len: 64 }, Seg { addr: 0x2000, len: 64 },
                Seg { addr: 0x3000, len: 64 }];
    assert_eq!(nbufs_for(&segs, 0), 0);
    assert_eq!(nbufs_for(&segs, 1), 1);
    assert_eq!(nbufs_for(&segs, 64), 1);
    // A buffer the transfer only partly filled is still consumed — it has the
    // caller's data in it and must not be handed out again.
    assert_eq!(nbufs_for(&segs, 65), 2);
    assert_eq!(nbufs_for(&segs, 192), 3);
}

/// An incremental group retires whole buffers and keeps the remainder of the
/// one it stopped inside, under the same id — which is what the completion's
/// "used again" flag announces.
#[test]
fn an_incremental_commit_keeps_the_remainder_under_the_same_id() {
    let ents = [e(0x1000, 64, 0), e(0x2000, 64, 1)];
    let c = inc_commit(&ents, 80, 0);
    assert_eq!(c.whole, 1);
    assert_eq!(c.partial, Some((0x2000 + 16, 48)));
    assert!(c.buf_more());
    assert_eq!(cqe_flags(0, c.buf_more()),
               IORING_CQE_F_BUFFER | IORING_CQE_F_BUF_MORE);
    // A transfer that lands exactly on a boundary leaves nothing behind.
    let c = inc_commit(&ents, 128, 0);
    assert_eq!(c.whole, 2);
    assert_eq!(c.partial, None);
    assert!(!c.buf_more());
    assert_eq!(cqe_flags(0, false) & IORING_CQE_F_BUF_MORE, 0);
}

/// No bytes moved: the buffer is untouched, so nothing is consumed and the id
/// is not reported as part-used either.
#[test]
fn an_incremental_commit_of_nothing_consumes_nothing() {
    let ents = [e(0x1000, 64, 0)];
    let c = inc_commit(&ents, 0, 0);
    assert_eq!(c, IncCommit { whole: 0, partial: None });
    assert!(!c.buf_more());
}

/// A remainder no larger than the group's registered floor is not worth
/// handing back: the buffer retires whole instead of returning nearly empty.
#[test]
fn a_remainder_under_the_registered_floor_retires_the_buffer() {
    let ents = [e(0x1000, 64, 0), e(0x2000, 64, 1)];
    // 8 bytes left, floor says "keep only more than 8": retired.
    let c = inc_commit(&ents, 56, 8);
    assert_eq!(c.whole, 1);
    assert_eq!(c.partial, None);
    // 9 bytes left: worth keeping.
    let c = inc_commit(&ents, 55, 8);
    assert_eq!(c.whole, 0);
    assert_eq!(c.partial, Some((0x1000 + 55, 9)));
}

/// The completion's id half is the run's first id, whatever else is set.
#[test]
fn the_completion_carries_the_first_id_in_its_upper_half() {
    for bid in [0u16, 1, 0x1234, u16::MAX] {
        let f = cqe_flags(bid, false);
        assert_eq!(f >> IORING_CQE_BUFFER_SHIFT, bid as u32);
        assert_ne!(f & IORING_CQE_F_BUFFER, 0);
    }
}
