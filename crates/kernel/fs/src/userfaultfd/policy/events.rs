// The cooperative half of the protocol, as decisions: which feature each
// address-space event needs, what its message carries, which queue a reader
// drains first, and the one check that refuses a resolve while a change is in
// flight.
//
// UNGATED, like the rest of `policy`: the queues and the blocking live behind
// the kernel target, so anything decided here is the only part a hosted test
// can reach — and every one of these is a contract a monitor observes.

use syscall::errno::Errno;
use vmm::{UffdEvent, UffdEventKind};

use crate::userfaultfd::uapi::*;

/// The feature bit a monitor must have negotiated to be told about `kind`.
/// # C: O(1)
pub fn event_feature(kind: UffdEventKind) -> u64 {
    match kind {
        UffdEventKind::Fork   => feature::EVENT_FORK,
        UffdEventKind::Remap  => feature::EVENT_REMAP,
        UffdEventKind::Remove => feature::EVENT_REMOVE,
        UffdEventKind::Unmap  => feature::EVENT_UNMAP,
    }
}

/// Whether a context with `ctx_features` asked to be told about `kind`.
///
/// A monitor that did not ask is not merely left unnotified: fork and remap
/// DROP the registration rather than let it follow a mapping the monitor cannot
/// see move. Keeping it would leave the monitor owning faults for an address
/// range it has no record of.
/// # C: O(1)
pub fn wants_event(ctx_features: u64, kind: UffdEventKind) -> bool {
    ctx_features & event_feature(kind) != 0
}

/// `uffd_msg.event` plus the three argument slots for one event.
///
/// The three slots are the message's union, so each event reuses the same
/// bytes: a remap fills all three, a remove/unmap two, a fork one. The fork
/// slot holds a DESCRIPTOR, which does not exist until the monitor reads the
/// event — the reader fills it, and this returns 0 for it.
/// # C: O(1)
pub fn event_msg(ev: UffdEvent) -> (u8, u64, u64, u64) {
    match ev {
        UffdEvent::Fork => (UFFD_EVENT_FORK, 0, 0, 0),
        UffdEvent::Remap { from, to, len } => (UFFD_EVENT_REMAP, from, to, len),
        UffdEvent::Remove { start, end } => (UFFD_EVENT_REMOVE, start, end, 0),
        UffdEvent::Unmap { start, end } => (UFFD_EVENT_UNMAP, start, end, 0),
    }
}

/// What a `read` on the fd should hand back next.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NextMessage {
    /// A blocked faulting thread's page-fault message.
    Fault,
    /// A blocked address-space change's announcement.
    Event,
    /// Nothing queued — the reader blocks, or reports EAGAIN.
    None,
}

/// Faults are drained BEFORE events, always.
///
/// Both queues hold a blocked thread, so either order terminates; the order
/// matters because a monitor typically resolves faults inline while handling
/// an event. Draining events first lets a queue of address-space changes stand
/// in front of the fault the monitor must resolve to make progress, and the
/// monitor deadlocks against threads it is holding.
/// # C: O(1)
pub fn next_message(has_fault: bool, has_event: bool) -> NextMessage {
    if has_fault { return NextMessage::Fault; }
    if has_event { return NextMessage::Event; }
    NextMessage::None
}

/// The one check that stands in front of every resolve: while a
/// non-cooperative address-space change is in flight, the layout the monitor
/// last saw is no longer the layout it would be resolving against, so the
/// resolve is refused as retryable rather than applied to the wrong mapping.
///
/// EAGAIN, not EBUSY: the monitor's correct response is to read the pending
/// event and reissue, which is exactly what the retryable code says.
/// # C: O(1)
pub fn check_mmap_changing(in_flight: u32) -> Result<(), Errno> {
    if in_flight != 0 { return Err(Errno::Eagain); }
    Ok(())
}

/// Whether the reply word of a fill-shaped ioctl carries the refusal.
///
/// The fills, the poison and the move report their outcome in a trailing reply
/// field as well as in the return value, and a monitor reads the errno out of
/// that field. Write-protect has no such field, so its refusal is the return
/// value alone — and because nothing has to be written back for it, its check
/// runs before the request object is even read, which makes EAGAIN beat the
/// EFAULT an unreadable object would produce. For the others the reply must be
/// written, so an unwritable object is EFAULT first.
/// # C: O(1)
pub fn refusal_is_written_back(has_reply_field: bool) -> bool { has_reply_field }

#[cfg(test)]
mod tests {
    use super::*;

    /// Each event is gated by its OWN feature. A shared or mistaken bit would
    /// deliver a monitor an event it never asked for — and, worse, would let
    /// the fork and remap paths keep a registration the monitor cannot track.
    #[test]
    fn every_event_is_gated_by_its_own_feature_bit() {
        let all = [UffdEventKind::Fork, UffdEventKind::Remap,
                   UffdEventKind::Remove, UffdEventKind::Unmap];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j { assert_ne!(event_feature(*a), event_feature(*b)); }
            }
            // Asking for exactly one feature enables exactly that one event.
            let feats = event_feature(*a);
            for b in &all {
                assert_eq!(wants_event(feats, *b), a == b);
            }
        }
        assert!(!wants_event(0, UffdEventKind::Fork));
    }

    /// Every event feature is offered by the handshake. A bit that is honoured
    /// but not offered can never be negotiated, so the behaviour behind it is
    /// unreachable; a bit offered but not honoured leaves the monitor waiting
    /// for an event that never comes.
    #[test]
    fn the_handshake_offers_exactly_the_event_features_that_are_honoured() {
        for k in [UffdEventKind::Fork, UffdEventKind::Remap,
                  UffdEventKind::Remove, UffdEventKind::Unmap] {
            assert_ne!(UFFD_API_FEATURES & event_feature(k), 0);
        }
    }

    /// The message encoding is the ABI: a remap fills three slots, a
    /// remove/unmap two, a fork none (its descriptor is created by the reader).
    #[test]
    fn each_event_encodes_into_the_message_slots_it_owns() {
        assert_eq!(event_msg(UffdEvent::Fork), (UFFD_EVENT_FORK, 0, 0, 0));
        assert_eq!(event_msg(UffdEvent::Remap { from: 0x1000, to: 0x9000, len: 0x2000 }),
                   (UFFD_EVENT_REMAP, 0x1000, 0x9000, 0x2000));
        assert_eq!(event_msg(UffdEvent::Remove { start: 0x1000, end: 0x3000 }),
                   (UFFD_EVENT_REMOVE, 0x1000, 0x3000, 0));
        assert_eq!(event_msg(UffdEvent::Unmap { start: 0x4000, end: 0x5000 }),
                   (UFFD_EVENT_UNMAP, 0x4000, 0x5000, 0));
    }

    /// The five event codes are distinct and distinct from the page-fault one:
    /// a monitor switches on this byte alone.
    #[test]
    fn the_event_codes_are_all_distinct() {
        let codes = [UFFD_EVENT_PAGEFAULT, UFFD_EVENT_FORK, UFFD_EVENT_REMAP,
                     UFFD_EVENT_REMOVE, UFFD_EVENT_UNMAP];
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() { if i != j { assert_ne!(a, b); } }
        }
    }

    /// A queued fault outranks a queued event. Reversing this starves the
    /// fault a monitor must resolve to make progress behind the changes it is
    /// being told about.
    #[test]
    fn a_queued_fault_is_read_before_a_queued_event() {
        assert_eq!(next_message(true, true), NextMessage::Fault);
        assert_eq!(next_message(true, false), NextMessage::Fault);
        assert_eq!(next_message(false, true), NextMessage::Event);
        assert_eq!(next_message(false, false), NextMessage::None);
    }

    /// A resolve is refused exactly while a change is in flight, and the code
    /// is the retryable one.
    #[test]
    fn a_resolve_is_refused_while_a_change_is_in_flight() {
        assert_eq!(check_mmap_changing(0), Ok(()));
        assert_eq!(check_mmap_changing(1), Err(Errno::Eagain));
        assert_eq!(check_mmap_changing(7), Err(Errno::Eagain));
    }
}
