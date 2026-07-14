use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::socket_error::SocketErrorEntry;

use super::Raw4Endpoint;

impl Raw4Endpoint {
    /// Match the reversed tuple quoted by one ICMP error. # C: O(1)
    pub(crate) fn matches_error(&self, iface: NetIfaceId, local: Ipv4Addr,
                                remote: Ipv4Addr) -> bool {
        let state = self.snapshot();
        state.accepting
            && state.bound_iface.is_none_or(|bound| bound == iface)
            && (state.local.is_unspecified() || state.local == local)
            && state.remote.is_none_or(|peer| peer == remote)
    }

    /// Publish Linux raw-socket pending and extended error state. # C: O(1) amortized
    pub(crate) fn publish_error(&self, entry: SocketErrorEntry, hard: bool) -> bool {
        let state = self.snapshot();
        if !state.accepting || !self.error.publish(entry, state.remote.is_some(), hard) {
            return false;
        }
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let poll = self.poll_subs.lock().clone();
        if let Some(subs) = poll.and_then(|weak| weak.upgrade()) {
            subs.notify_mask(vfs::POLL_ERR);
        }
        true
    }
}
