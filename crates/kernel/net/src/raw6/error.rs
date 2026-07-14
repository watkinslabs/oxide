use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::socket_error::SocketErrorEntry;

use super::matching::{tuple_matches, MatchInput};
use super::Raw6Endpoint;

impl Raw6Endpoint {
    /// Match the reversed tuple quoted by one ICMPv6 error. # C: O(1)
    pub(crate) fn matches_error(&self, iface: NetIfaceId, local: Ipv6Addr,
                                remote: Ipv6Addr) -> bool {
        let state = self.state.lock();
        tuple_matches(self.net_ns(), self.protocol(), &state, &MatchInput {
            net_ns: self.net_ns(), protocol: self.protocol(), src: remote,
            dst: local, iface,
        })
    }

    /// Publish Linux raw-socket pending and extended error state. # C: O(1) amortized
    pub(crate) fn publish_error(&self, entry: SocketErrorEntry, hard: bool) -> bool {
        let state = self.state.lock();
        if !state.accepting || !self.error.publish(entry, state.peer.is_some(), hard) {
            return false;
        }
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let poll = self.poll_subs.lock().clone();
        if let Some(subs) = poll.and_then(|weak| weak.upgrade()) {
            subs.notify_mask(vfs::POLL_ERR);
        }
        true
    }
}
