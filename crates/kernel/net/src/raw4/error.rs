use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::socket_error::SocketErrorEntry;

use super::Raw4Endpoint;

const ICMP_CODE_FRAG_NEEDED: u8 = 4;

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

    /// Publish Linux raw-socket pending and extended error state. Test-only:
    /// the live IPv4 ICMP path always routes through `publish_quoted_error`, so
    /// it can honour `IP_HDRINCL`. # C: O(1) amortized
    #[cfg(test)]
    pub(crate) fn publish_error(&self, entry: SocketErrorEntry, hard: bool) -> bool {
        self.publish_error_inner(entry, hard, None)
    }

    /// Select Linux `IP_HDRINCL` error payload and publish one raw error. # C: O(packet)
    pub(crate) fn publish_quoted_error(&self, entry: SocketErrorEntry, hard: bool,
                                      quoted_ip: &[u8]) -> bool {
        self.publish_error_inner(entry, hard, Some(quoted_ip))
    }

    fn publish_error_inner(&self, mut entry: SocketErrorEntry, hard: bool,
                           quoted_ip: Option<&[u8]>) -> bool {
        let state = self.snapshot();
        if state.hdrincl {
            if let Some(quoted) = quoted_ip { entry.payload = quoted.to_vec(); }
        }
        let frag_needed = entry.kind == crate::icmp::ICMP_TYPE_DEST_UNREACH
            && entry.code == ICMP_CODE_FRAG_NEEDED;
        let raw_hard = if frag_needed {
            self.pmtudisc() != crate::uapi::IP_PMTUDISC_DONT
        } else { hard };
        if !state.accepting || !self.error.publish(entry, state.remote.is_some(), raw_hard) {
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
