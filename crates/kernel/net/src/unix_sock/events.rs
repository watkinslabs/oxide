use vfs;
use sched;

use super::{UnixEnd, UnixMsgPair, UnixPair};

/// F181a: wake the PEER end's epoll subscribers (the end whose
/// `read` would now succeed). When `end == A` we just wrote to
/// a_to_b (peer = B), so wake end_b_subs; vice versa.
/// Falls back to global epoll broadcast when peer's subs slot is
/// empty (binding race) so no events get silently swallowed.
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn wake_peer_subs(pair: &UnixPair, end: UnixEnd) {
    let slot = match end {
        UnixEnd::A => pair.end_b_subs.lock().clone(),
        UnixEnd::B => pair.end_a_subs.lock().clone(),
    };
    if let Some(weak) = slot {
        if let Some(subs) = weak.upgrade() {
            subs.notify();
            return;
        }
    }
    sched::live::notify_epoll_waiters();
}

/// F181a: msgpair sibling of `wake_peer_subs`.
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn wake_msgpair_peer_subs(pair: &UnixMsgPair, end: UnixEnd) {
    let slot = match end {
        UnixEnd::A => pair.end_b_subs.lock().clone(),
        UnixEnd::B => pair.end_a_subs.lock().clone(),
    };
    if let Some(weak) = slot {
        if let Some(subs) = weak.upgrade() {
            subs.notify();
            return;
        }
    }
    sched::live::notify_epoll_waiters();
}
