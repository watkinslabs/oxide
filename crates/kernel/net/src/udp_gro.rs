// `UDP_GRO` receive coalescing: the rule that decides whether an arriving
// datagram joins the run already queued at a socket, or starts its own.
//
// Ungated on purpose — this is the decision, and a target-gated module would
// compile its tests away silently. The endpoints in `stack`/`stack_ipv6`
// execute it; nothing else reimplements it.

/// Most datagrams one coalesced receive may carry.
pub const UDP_GRO_CNT_MAX: usize = 64;

/// Identifies the receive batch a run was opened in.
///
/// Coalescing is bounded in time as well as in shape: an interface merges only
/// the datagrams it hands to the protocol in ONE receive batch, and every open
/// run is closed when that batch ends. Without the bound a run would keep
/// absorbing datagrams that arrived arbitrarily far apart, which no interface
/// does.
static RX_BATCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The batch a datagram arriving now belongs to. # C: O(1)
pub fn current_batch() -> u64 { RX_BATCH.load(core::sync::atomic::Ordering::Acquire) }

/// End the current receive batch, closing every run still open in it. An
/// interface driver calls this once its poll has handed over everything it
/// drained. # C: O(1)
pub fn end_rx_batch() { RX_BATCH.fetch_add(1, core::sync::atomic::Ordering::AcqRel); }

/// The coalescing state of one queued datagram.
///
/// `seg_size` is the length of the run's FIRST datagram and never changes as
/// the run grows, because that is the size the reader needs to split the
/// merged payload back into segments. A run closes when it can accept nothing
/// further: it reached the segment cap, or it absorbed a short final segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroRun {
    pub seg_size: usize,
    pub segments: usize,
    pub closed: bool,
    /// The receive batch this run was opened in; a later batch cannot extend it.
    pub batch: u64,
}

impl GroRun {
    /// A datagram that has not been coalesced with anything. # C: O(1)
    pub fn single(len: usize, batch: u64) -> Self {
        Self { seg_size: len, segments: 1, closed: true, batch }
    }

    /// A datagram that may still absorb further segments. # C: O(1)
    pub fn open(len: usize, batch: u64) -> Self {
        Self { seg_size: len, segments: 1, closed: false, batch }
    }

    /// The segment size this receive reports, or `None` when nothing was
    /// coalesced. A receive of ONE datagram carries no segmentation size, so
    /// the reader is told nothing and treats the payload as one datagram.
    /// # C: O(1)
    pub fn cmsg_seg_size(&self) -> Option<usize> {
        (self.segments > 1).then_some(self.seg_size)
    }

    /// Absorb one more segment of `len` bytes. # C: O(1)
    pub fn extend(&mut self, len: usize) {
        self.segments += 1;
        if len < self.seg_size || self.segments >= UDP_GRO_CNT_MAX { self.closed = true; }
    }
}

/// What an arriving datagram does to the queue tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroAdmit {
    /// Queue it as its own receive; it may become a run head.
    Separate { open: bool },
    /// Append its payload to the tail datagram.
    Merge,
}

/// A datagram may head a coalescing run only if it could also be merged into
/// one: an empty datagram carries no segment size, and a datagram whose
/// checksum was suppressed cannot be coalesced at all, for symmetry with the
/// transmit side, which refuses to segment a checksum-suppressed write.
/// # C: O(1)
pub fn may_coalesce(len: usize, checksum_zero: bool) -> bool { len != 0 && !checksum_zero }

/// Decide where an arriving datagram goes.
///
/// `tail` is the run currently at the back of the socket's queue, and
/// `same_flow` says whether that tail came from the same source, to the same
/// local endpoint, over the same interface, with the same network-header
/// values. A datagram LONGER than the run's segment size never joins — it
/// ends the run and starts a new one — while a SHORTER one joins and closes
/// the run, which is how a segmented write's short final segment arrives.
/// # C: O(1)
pub fn admit(tail: Option<&GroRun>, same_flow: bool, len: usize, checksum_zero: bool,
    enabled: bool, batch: u64) -> GroAdmit
{
    let open = enabled && may_coalesce(len, checksum_zero);
    if !open { return GroAdmit::Separate { open: false }; }
    let Some(tail) = tail else { return GroAdmit::Separate { open: true } };
    if tail.closed || tail.batch != batch || !same_flow || len > tail.seg_size {
        return GroAdmit::Separate { open: true };
    }
    GroAdmit::Merge
}

/// Whether the interface a datagram arrived on offers receive coalescing.
///
/// Coalescing is a device receive-path feature, not a property of the socket:
/// a loopback delivery is handed straight to the protocol and is never
/// coalesced, so a local sender's datagrams reach the reader one by one no
/// matter what the receiving socket asked for. # C: O(1)
pub fn device_offers_gro(hardware_type: u16) -> bool {
    hardware_type != crate::uapi::ARPHRD_LOOPBACK
}

/// Whether a delivered datagram is a coalescing candidate at all.
///
/// A reassembled datagram never is. A fragment is refused coalescing before it
/// ever reaches the transport, so a datagram rebuilt from fragments cannot
/// coalesce either — the same answer, reached earlier in the path.
/// # C: O(1)
pub fn coalescable_receive(offered: bool, frag_max: u32) -> bool { offered && frag_max == 0 }

/// [`coalescable_receive`] for IPv4, which additionally refuses any datagram
/// whose header carried options.
///
/// A header longer than the fixed twenty bytes is rejected from coalescing
/// outright rather than compared, so the option area a coalesced receive
/// publishes can never disagree with the datagrams merged into it. # C: O(1)
pub fn coalescable_v4(offered: bool, frag_max: u32, option_bytes: usize) -> bool {
    coalescable_receive(offered, frag_max) && option_bytes == 0
}

/// The `UDP_GRO` control message a receive publishes, if any.
///
/// It exists only for a receive several datagrams were coalesced into, and
/// only while the socket still has the option engaged — a socket that turned
/// coalescing off between delivery and the read is told nothing, and a receive
/// of one datagram never carries a segment size. # C: O(1)
pub fn reported_seg_size(enabled: bool, coalesced: Option<i32>) -> Option<i32> {
    if !enabled { return None; }
    coalesced
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_never_spans_two_receive_batches() {
        let run = GroRun::open(1_000, 7);
        assert_eq!(admit(Some(&run), true, 1_000, false, true, 7), GroAdmit::Merge);
        assert_eq!(admit(Some(&run), true, 1_000, false, true, 8),
            GroAdmit::Separate { open: true },
            "datagrams the interface handed over in separate batches never merge");
    }

    #[test]
    fn ending_a_batch_moves_the_counter_forward() {
        let before = current_batch();
        end_rx_batch();
        assert_ne!(current_batch(), before);
    }

    #[test]
    fn loopback_delivery_is_never_coalesced() {
        assert!(!device_offers_gro(crate::uapi::ARPHRD_LOOPBACK));
        assert!(device_offers_gro(crate::uapi::ARPHRD_ETHER));
    }

    #[test]
    fn a_reassembled_datagram_is_never_a_coalescing_candidate() {
        // A fragment is refused before the transport, so the datagram rebuilt
        // from fragments is refused too.
        assert!(coalescable_receive(true, 0));
        assert!(!coalescable_receive(true, 1_400));
        assert!(!coalescable_receive(false, 0));
    }

    #[test]
    fn an_optioned_ipv4_header_is_never_a_coalescing_candidate() {
        // A header longer than the fixed twenty bytes is refused outright
        // rather than compared against the run.
        assert!(coalescable_v4(true, 0, 0));
        assert!(!coalescable_v4(true, 0, 4));
        // And the shared refusals still apply.
        assert!(!coalescable_v4(true, 1_400, 0));
        assert!(!coalescable_v4(false, 0, 0));
    }

    #[test]
    fn the_control_message_needs_both_a_coalesced_receive_and_the_option() {
        assert_eq!(reported_seg_size(true, Some(1_400)), Some(1_400));
        assert_eq!(reported_seg_size(true, None), None,
            "a receive of one datagram carries no segment size");
        assert_eq!(reported_seg_size(false, Some(1_400)), None,
            "the option must still be engaged when the receive is read");
        assert_eq!(reported_seg_size(false, None), None);
    }

    #[test]
    fn a_lone_datagram_reports_no_segment_size() {
        assert_eq!(GroRun::single(1_000, 0).cmsg_seg_size(), None);
        assert_eq!(GroRun::open(1_000, 0).cmsg_seg_size(), None);
    }

    #[test]
    fn a_coalesced_receive_reports_the_first_datagrams_length() {
        let mut run = GroRun::open(1_000, 0);
        run.extend(1_000);
        assert_eq!(run.cmsg_seg_size(), Some(1_000));
        assert_eq!(run.segments, 2);
        assert!(!run.closed);
    }

    #[test]
    fn a_short_segment_joins_the_run_and_ends_it() {
        let mut run = GroRun::open(1_000, 0);
        run.extend(1_000);
        run.extend(400);
        assert!(run.closed, "a short final segment closes the run");
        // The reported size stays the FULL segment size, not the short tail's.
        assert_eq!(run.cmsg_seg_size(), Some(1_000));
        assert_eq!(run.segments, 3);
    }

    #[test]
    fn a_run_stops_growing_at_the_segment_cap() {
        let mut run = GroRun::open(100, 0);
        for _ in 1..UDP_GRO_CNT_MAX { run.extend(100); }
        assert_eq!(run.segments, UDP_GRO_CNT_MAX);
        assert!(run.closed);
        assert_eq!(admit(Some(&run), true, 100, false, true, 0), GroAdmit::Separate { open: true });
    }

    #[test]
    fn coalescing_never_happens_with_the_option_off() {
        let run = GroRun::open(1_000, 0);
        assert_eq!(admit(Some(&run), true, 1_000, false, false, 0),
            GroAdmit::Separate { open: false });
        assert_eq!(admit(None, true, 1_000, false, false, 0), GroAdmit::Separate { open: false });
    }

    #[test]
    fn a_suppressed_checksum_is_never_coalesced_in_either_direction() {
        assert!(!may_coalesce(1_000, true));
        // It cannot join a run...
        let run = GroRun::open(1_000, 0);
        assert_eq!(admit(Some(&run), true, 1_000, true, true, 0),
            GroAdmit::Separate { open: false });
        // ...and it cannot head one either, so the datagram after it is also
        // delivered on its own.
        assert_eq!(admit(None, true, 1_000, true, true, 0), GroAdmit::Separate { open: false });
    }

    #[test]
    fn an_empty_datagram_is_never_coalesced() {
        assert!(!may_coalesce(0, false));
        let run = GroRun::open(1_000, 0);
        assert_eq!(admit(Some(&run), true, 0, false, true, 0), GroAdmit::Separate { open: false });
    }

    #[test]
    fn equal_sized_datagrams_of_one_flow_merge() {
        let run = GroRun::open(1_000, 0);
        assert_eq!(admit(Some(&run), true, 1_000, false, true, 0), GroAdmit::Merge);
    }

    #[test]
    fn a_shorter_datagram_merges_but_a_longer_one_does_not() {
        let run = GroRun::open(1_000, 0);
        assert_eq!(admit(Some(&run), true, 999, false, true, 0), GroAdmit::Merge);
        assert_eq!(admit(Some(&run), true, 1_001, false, true, 0),
            GroAdmit::Separate { open: true });
    }

    #[test]
    fn a_different_flow_never_merges_but_still_starts_its_own_run() {
        let run = GroRun::open(1_000, 0);
        assert_eq!(admit(Some(&run), false, 1_000, false, true, 0),
            GroAdmit::Separate { open: true });
    }

    #[test]
    fn a_closed_run_absorbs_nothing_further() {
        let mut run = GroRun::open(1_000, 0);
        run.extend(500);
        assert!(run.closed);
        assert_eq!(admit(Some(&run), true, 500, false, true, 0), GroAdmit::Separate { open: true });
        assert_eq!(admit(Some(&run), true, 1_000, false, true, 0), GroAdmit::Separate { open: true });
    }

    #[test]
    fn a_single_delivered_datagram_is_closed_and_reports_nothing() {
        let run = GroRun::single(1_000, 0);
        assert!(run.closed);
        assert_eq!(run.cmsg_seg_size(), None);
        assert_eq!(admit(Some(&run), true, 1_000, false, true, 0), GroAdmit::Separate { open: true });
    }
}
