use super::{UnixEnd, UnixMsgPair, UnixPair};

/// Wake the PEER end's epoll subscribers -- the end whose `read` would now
/// succeed. When `end == A` we just wrote to a_to_b (peer = B), and vice versa.
///
/// The subscriber list is resolved through the peer's bound open file, the
/// same `file.inode()` route `EPOLL_CTL_ADD` resolves it through, so the list
/// notified here is BY CONSTRUCTION the one epoll subscribed to. The pair used
/// to keep its own per-end `Weak` slot, registered by whichever socket
/// constructor ran -- a second copy of the same fact, and when a connect or
/// accept re-pointed the end at a different socket the copy went stale and the
/// wake went to a list nobody watched, while the task slept on a readable fd.
///
/// No bound file means no epoll interest can exist on that end (an interest
/// needs an fd, an fd needs the file), and an interest ADDed after this wake
/// re-checks readiness once it has subscribed -- so there is nothing to miss.
pub(crate) fn wake_peer_subs(pair: &UnixPair, end: UnixEnd, events: u32) {
    let peer = match end { UnixEnd::A => UnixEnd::B, UnixEnd::B => UnixEnd::A };
    if let Some(file) = pair.gc_node(peer).owner_file() {
        if let Some(subs) = file.inode().poll_subscribers_arc() {
            subs.notify_mask(events);
            return;
        }
        // A socket inode always carries its subscriber list; reaching here
        // means the file is not the socket we think it is. Wake broadly
        // rather than swallow the event.
        #[cfg(target_os = "oxide-kernel")]
        sched::live::notify_epoll_waiters();
    }
}

/// Msgpair sibling of `wake_peer_subs`, with the same single-source contract.
pub(crate) fn wake_msgpair_peer_subs(pair: &UnixMsgPair, end: UnixEnd, events: u32) {
    let peer = match end { UnixEnd::A => UnixEnd::B, UnixEnd::B => UnixEnd::A };
    if let Some(file) = pair.gc_node(peer).owner_file() {
        if let Some(subs) = file.inode().poll_subscribers_arc() {
            subs.notify_mask(events);
            return;
        }
        #[cfg(target_os = "oxide-kernel")]
        sched::live::notify_epoll_waiters();
    }
}
