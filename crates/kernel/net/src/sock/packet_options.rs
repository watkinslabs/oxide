use super::*;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct PacketOptions {
    ignore_outgoing: AtomicBool,
}

impl PacketOptions {
    /// Read outgoing-observation suppression. # C: O(1)
    pub(crate) fn ignore_outgoing(&self) -> bool {
        self.ignore_outgoing.load(Ordering::Acquire)
    }

    fn set_ignore_outgoing(&self, enabled: bool) {
        self.ignore_outgoing.store(enabled, Ordering::Release);
    }
}

impl InetSocket {
    /// Set Linux `PACKET_IGNORE_OUTGOING` on an AF_PACKET socket. # C: O(1)
    pub fn set_packet_ignore_outgoing(&self, enabled: bool) -> crate::NetResult<()> {
        let kind = self.kind.lock();
        let SockKind::Packet { options, .. } = &*kind else {
            return Err(crate::NetError::Enoprotoopt);
        };
        options.set_ignore_outgoing(enabled);
        Ok(())
    }

    /// Read Linux `PACKET_IGNORE_OUTGOING` from an AF_PACKET socket. # C: O(1)
    pub fn packet_ignore_outgoing(&self) -> crate::NetResult<bool> {
        let kind = self.kind.lock();
        let SockKind::Packet { options, .. } = &*kind else {
            return Err(crate::NetError::Enoprotoopt);
        };
        Ok(options.ignore_outgoing())
    }
}
