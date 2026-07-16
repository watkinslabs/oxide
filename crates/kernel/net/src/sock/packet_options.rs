use super::*;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct PacketOptions {
    auxdata: AtomicBool,
    ignore_outgoing: AtomicBool,
    origdev: AtomicBool,
}

impl PacketOptions {
    /// Read outgoing-observation suppression. # C: O(1)
    pub(crate) fn ignore_outgoing(&self) -> bool {
        self.ignore_outgoing.load(Ordering::Acquire)
    }

    fn set_ignore_outgoing(&self, enabled: bool) {
        self.ignore_outgoing.store(enabled, Ordering::Release);
    }

    /// Read original-device address selection. # C: O(1)
    pub(crate) fn origdev(&self) -> bool { self.origdev.load(Ordering::Acquire) }

    fn set_auxdata(&self, enabled: bool) { self.auxdata.store(enabled, Ordering::Release); }

    fn set_origdev(&self, enabled: bool) { self.origdev.store(enabled, Ordering::Release); }
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

    /// Set Linux `PACKET_AUXDATA` on an AF_PACKET socket. # C: O(1)
    pub fn set_packet_auxdata(&self, enabled: bool) -> crate::NetResult<()> {
        self.with_packet_options(|options| options.set_auxdata(enabled))
    }

    /// Read Linux `PACKET_AUXDATA` from an AF_PACKET socket. # C: O(1)
    pub fn packet_auxdata(&self) -> crate::NetResult<bool> {
        self.with_packet_options(|options| options.auxdata.load(Ordering::Acquire))
    }

    /// Set Linux `PACKET_ORIGDEV` on an AF_PACKET socket. # C: O(1)
    pub fn set_packet_origdev(&self, enabled: bool) -> crate::NetResult<()> {
        self.with_packet_options(|options| options.set_origdev(enabled))
    }

    /// Read Linux `PACKET_ORIGDEV` from an AF_PACKET socket. # C: O(1)
    pub fn packet_origdev(&self) -> crate::NetResult<bool> {
        self.with_packet_options(PacketOptions::origdev)
    }

    fn with_packet_options<T>(&self, op: impl FnOnce(&PacketOptions) -> T)
        -> crate::NetResult<T>
    {
        let kind = self.kind.lock();
        let SockKind::Packet { options, .. } = &*kind else {
            return Err(crate::NetError::Enoprotoopt);
        };
        Ok(op(options))
    }
}
