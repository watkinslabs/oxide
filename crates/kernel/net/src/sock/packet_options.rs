use super::*;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, Ordering};

const SOCK_RAW: u8 = 3;

#[derive(Default)]
pub struct PacketOptions {
    auxdata: AtomicBool,
    ignore_outgoing: AtomicBool,
    loss: AtomicBool,
    origdev: AtomicBool,
    version: AtomicU8,
    reserve: AtomicU32,
    copy_thresh: AtomicI32,
    vnet_hdr_size: AtomicU32,
    timestamp: AtomicI32,
    tx_has_off: AtomicBool,
    qdisc_bypass: AtomicBool,
}

impl PacketOptions {
    /// Read outgoing-observation suppression. # C: O(1)
    pub(crate) fn ignore_outgoing(&self) -> bool {
        self.ignore_outgoing.load(Ordering::Acquire)
    }

    fn set_ignore_outgoing(&self, enabled: bool) {
        self.ignore_outgoing.store(enabled, Ordering::Release);
    }

    fn set_loss(&self, enabled: bool) { self.loss.store(enabled, Ordering::Release); }

    fn loss(&self) -> bool { self.loss.load(Ordering::Acquire) }

    /// Read original-device address selection. # C: O(1)
    pub(crate) fn origdev(&self) -> bool { self.origdev.load(Ordering::Acquire) }

    fn set_auxdata(&self, enabled: bool) { self.auxdata.store(enabled, Ordering::Release); }

    fn set_origdev(&self, enabled: bool) { self.origdev.store(enabled, Ordering::Release); }

    pub(crate) fn set_version(&self, version: u8) { self.version.store(version, Ordering::Release); }

    pub(crate) fn version(&self) -> u8 { self.version.load(Ordering::Acquire) }

    pub(crate) fn set_reserve(&self, reserve: u32) { self.reserve.store(reserve, Ordering::Release); }

    pub(crate) fn reserve(&self) -> u32 { self.reserve.load(Ordering::Acquire) }

    fn set_copy_thresh(&self, value: i32) { self.copy_thresh.store(value, Ordering::Release); }

    pub(crate) fn copy_thresh(&self) -> i32 { self.copy_thresh.load(Ordering::Acquire) }

    fn set_vnet_hdr_size(&self, value: u32) {
        self.vnet_hdr_size.store(value, Ordering::Release);
    }

    pub(crate) fn vnet_hdr_size(&self) -> u32 { self.vnet_hdr_size.load(Ordering::Acquire) }

    fn set_timestamp(&self, value: i32) { self.timestamp.store(value, Ordering::Release); }

    pub(crate) fn timestamp(&self) -> i32 { self.timestamp.load(Ordering::Acquire) }

    fn set_tx_has_off(&self, enabled: bool) { self.tx_has_off.store(enabled, Ordering::Release); }

    fn tx_has_off(&self) -> bool { self.tx_has_off.load(Ordering::Acquire) }

    fn set_qdisc_bypass(&self, enabled: bool) {
        self.qdisc_bypass.store(enabled, Ordering::Release);
    }

    fn qdisc_bypass(&self) -> bool { self.qdisc_bypass.load(Ordering::Acquire) }
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

    /// Select the Linux packet header version while no ring exists. # C: O(1)
    pub fn set_packet_version(&self, version: u8) -> crate::NetResult<()> {
        if !matches!(version, crate::uapi::TPACKET_V1 | crate::uapi::TPACKET_V2
            | crate::uapi::TPACKET_V3) { return Err(crate::NetError::Einval); }
        let rings = self.packet_rings.lock();
        if rings.busy() { return Err(crate::NetError::Ebusy); }
        let result = self.with_packet_options(|options| options.set_version(version));
        drop(rings);
        result
    }

    /// Read the selected Linux packet header version. # C: O(1)
    pub fn packet_version(&self) -> crate::NetResult<u8> {
        self.with_packet_options(PacketOptions::version)
    }

    /// Set Linux `PACKET_RESERVE` while no ring exists. # C: O(1)
    pub fn set_packet_reserve(&self, reserve: u32) -> crate::NetResult<()> {
        if reserve > i32::MAX as u32 { return Err(crate::NetError::Einval); }
        let rings = self.packet_rings.lock();
        if rings.busy() { return Err(crate::NetError::Ebusy); }
        let result = self.with_packet_options(|options| options.set_reserve(reserve));
        drop(rings);
        result
    }

    /// Read Linux `PACKET_RESERVE`. # C: O(1)
    pub fn packet_reserve(&self) -> crate::NetResult<u32> {
        self.with_packet_options(PacketOptions::reserve)
    }

    /// Set Linux `PACKET_LOSS` while no packet ring exists. # C: O(1)
    pub fn set_packet_loss(&self, enabled: bool) -> crate::NetResult<()> {
        let rings = self.packet_rings.lock();
        if rings.busy() { return Err(crate::NetError::Ebusy); }
        let result = self.with_packet_options(|options| options.set_loss(enabled));
        drop(rings);
        result
    }

    /// Read Linux `PACKET_LOSS`. # C: O(1)
    pub fn packet_loss(&self) -> crate::NetResult<bool> {
        self.with_packet_options(PacketOptions::loss)
    }

    /// Set Linux `PACKET_COPY_THRESH`. # C: O(1)
    pub fn set_packet_copy_thresh(&self, value: i32) -> crate::NetResult<()> {
        self.with_packet_options(|options| options.set_copy_thresh(value))
    }

    /// Read Linux `PACKET_COPY_THRESH`. # C: O(1)
    pub fn packet_copy_thresh(&self) -> crate::NetResult<i32> {
        self.with_packet_options(PacketOptions::copy_thresh)
    }

    /// Set Linux `PACKET_VNET_HDR_SZ` while no packet ring exists. # C: O(1)
    pub fn set_packet_vnet_hdr_size(&self, value: u32) -> crate::NetResult<()> {
        if !matches!(value, 0 | super::packet_virtio::VNET_HEADER_LEN
            | super::packet_virtio::VNET_MRG_HEADER_LEN) {
            return Err(crate::NetError::Einval);
        }
        let rings = self.packet_rings.lock();
        let kind = self.kind.lock();
        let SockKind::Packet { sock_type, options, .. } = &*kind else {
            return Err(crate::NetError::Enoprotoopt);
        };
        if sock_type.load(Ordering::Acquire) != SOCK_RAW { return Err(crate::NetError::Einval); }
        if rings.busy() { return Err(crate::NetError::Ebusy); }
        options.set_vnet_hdr_size(value);
        Ok(())
    }

    /// Read Linux `PACKET_VNET_HDR_SZ`. # C: O(1)
    pub fn packet_vnet_hdr_size(&self) -> crate::NetResult<u32> {
        self.with_packet_options(PacketOptions::vnet_hdr_size)
    }

    /// Set Linux `PACKET_TIMESTAMP`. # C: O(1)
    pub fn set_packet_timestamp(&self, value: i32) -> crate::NetResult<()> {
        self.with_packet_options(|options| options.set_timestamp(value))
    }

    /// Read Linux `PACKET_TIMESTAMP`. # C: O(1)
    pub fn packet_timestamp(&self) -> crate::NetResult<i32> {
        self.with_packet_options(PacketOptions::timestamp)
    }

    /// Set Linux `PACKET_TX_HAS_OFF`, unless a packet ring already exists. # C: O(1)
    pub fn set_packet_tx_has_off(&self, enabled: bool) -> crate::NetResult<()> {
        let rings = self.packet_rings.lock();
        let kind = self.kind.lock();
        let SockKind::Packet { options, .. } = &*kind else {
            return Err(crate::NetError::Enoprotoopt);
        };
        if !rings.busy() { options.set_tx_has_off(enabled); }
        Ok(())
    }

    /// Read Linux `PACKET_TX_HAS_OFF`. # C: O(1)
    pub fn packet_tx_has_off(&self) -> crate::NetResult<bool> {
        self.with_packet_options(PacketOptions::tx_has_off)
    }

    /// Set Linux `PACKET_QDISC_BYPASS`. # C: O(1)
    pub fn set_packet_qdisc_bypass(&self, enabled: bool) -> crate::NetResult<()> {
        self.with_packet_options(|options| options.set_qdisc_bypass(enabled))
    }

    /// Read Linux `PACKET_QDISC_BYPASS`. # C: O(1)
    pub fn packet_qdisc_bypass(&self) -> crate::NetResult<bool> {
        self.with_packet_options(PacketOptions::qdisc_bypass)
    }

    /// Read and reset packet admission statistics under the queue owner. # C: O(1)
    pub fn take_packet_statistics(&self) -> crate::NetResult<(u8, PacketStatistics)> {
        let kind = self.kind.lock();
        let SockKind::Packet { options, rx, .. } = &*kind else {
            return Err(crate::NetError::Enoprotoopt);
        };
        let result = (options.version(), rx.lock().take_statistics());
        Ok(result)
    }

    #[cfg(any(test, feature = "hosted"))]
    /// Drain packet frames through the queue owner for hosted integration tests. # C: O(N)
    pub fn take_packet_test_frames(&self) -> crate::NetResult<Vec<PacketFrame>> {
        let kind = self.kind.lock();
        let SockKind::Packet { rx, .. } = &*kind else {
            return Err(crate::NetError::Enoprotoopt);
        };
        let limit = self.opts.rcvbuf.load(Ordering::Acquire).max(0) as usize;
        let frames = rx.lock().take_all(limit);
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DGRAM: u8 = 2;

    fn socket() -> InetSocket { InetSocket::new_packet(crate::eth_p::ALL, SOCK_RAW) }

    fn request() -> PacketRingRequest {
        PacketRingRequest { block_size: 4096, block_nr: 1, frame_size: 256, frame_nr: 16,
            ..PacketRingRequest::default() }
    }

    #[test]
    fn packet_loss_defaults_off_and_tracks_boolean_state() {
        let socket = socket();
        assert_eq!(socket.packet_loss(), Ok(false));
        socket.set_packet_loss(true).unwrap();
        assert_eq!(socket.packet_loss(), Ok(true));
        socket.set_packet_loss(false).unwrap();
        assert_eq!(socket.packet_loss(), Ok(false));
    }

    #[test]
    fn packet_loss_change_is_busy_with_either_ring() {
        for kind in [PacketRingKind::Rx, PacketRingKind::Tx] {
            let socket = socket();
            socket.set_packet_ring(kind, request()).unwrap();
            assert_eq!(socket.set_packet_loss(true), Err(crate::NetError::Ebusy));
            assert_eq!(socket.packet_loss(), Ok(false));
        }
    }

    #[test]
    fn packet_offload_options_default_and_preserve_exact_state() {
        let socket = socket();
        assert_eq!(socket.packet_copy_thresh(), Ok(0));
        assert_eq!(socket.packet_vnet_hdr_size(), Ok(0));
        assert_eq!(socket.packet_timestamp(), Ok(0));
        assert_eq!(socket.packet_tx_has_off(), Ok(false));
        assert_eq!(socket.packet_qdisc_bypass(), Ok(false));
        socket.set_packet_copy_thresh(i32::MIN).unwrap();
        socket.set_packet_vnet_hdr_size(super::packet_virtio::VNET_HEADER_LEN).unwrap();
        socket.set_packet_timestamp(i32::MAX).unwrap();
        socket.set_packet_tx_has_off(true).unwrap();
        socket.set_packet_qdisc_bypass(true).unwrap();
        assert_eq!(socket.packet_copy_thresh(), Ok(i32::MIN));
        assert_eq!(socket.packet_vnet_hdr_size(), Ok(super::packet_virtio::VNET_HEADER_LEN));
        assert_eq!(socket.packet_timestamp(), Ok(i32::MAX));
        assert_eq!(socket.packet_tx_has_off(), Ok(true));
        assert_eq!(socket.packet_qdisc_bypass(), Ok(true));
    }

    #[test]
    fn packet_vnet_hdr_size_validates_type_and_size_before_ring_state() {
        let dgram = InetSocket::new_packet(crate::eth_p::ALL, DGRAM);
        assert_eq!(dgram.set_packet_vnet_hdr_size(super::packet_virtio::VNET_HEADER_LEN),
            Err(crate::NetError::Einval));
        let socket = socket();
        socket.set_packet_ring(PacketRingKind::Rx, request()).unwrap();
        assert_eq!(socket.set_packet_vnet_hdr_size(11), Err(crate::NetError::Einval));
        assert_eq!(socket.set_packet_vnet_hdr_size(super::packet_virtio::VNET_HEADER_LEN),
            Err(crate::NetError::Ebusy));
        assert_eq!(socket.packet_vnet_hdr_size(), Ok(0));
    }

    #[test]
    fn packet_vnet_hdr_size_is_busy_with_either_ring_and_keeps_state() {
        for kind in [PacketRingKind::Rx, PacketRingKind::Tx] {
            let socket = socket();
            socket.set_packet_vnet_hdr_size(super::packet_virtio::VNET_HEADER_LEN).unwrap();
            socket.set_packet_ring(kind, request()).unwrap();
            assert_eq!(socket.set_packet_vnet_hdr_size(super::packet_virtio::VNET_MRG_HEADER_LEN),
                Err(crate::NetError::Ebusy));
            assert_eq!(socket.packet_vnet_hdr_size(), Ok(super::packet_virtio::VNET_HEADER_LEN));
        }
    }

    #[test]
    fn packet_tx_has_off_succeeds_without_change_with_either_ring() {
        for kind in [PacketRingKind::Rx, PacketRingKind::Tx] {
            let socket = socket();
            socket.set_packet_tx_has_off(true).unwrap();
            socket.set_packet_ring(kind, request()).unwrap();
            assert_eq!(socket.set_packet_tx_has_off(false), Ok(()));
            assert_eq!(socket.packet_tx_has_off(), Ok(true));
        }
    }

    #[test]
    fn packet_copy_timestamp_and_qdisc_remain_mutable_with_rings() {
        for kind in [PacketRingKind::Rx, PacketRingKind::Tx] {
            let socket = socket();
            socket.set_packet_ring(kind, request()).unwrap();
            socket.set_packet_copy_thresh(-7).unwrap();
            socket.set_packet_timestamp(-9).unwrap();
            socket.set_packet_qdisc_bypass(true).unwrap();
            assert_eq!(socket.packet_copy_thresh(), Ok(-7));
            assert_eq!(socket.packet_timestamp(), Ok(-9));
            assert_eq!(socket.packet_qdisc_bypass(), Ok(true));
        }
    }

    #[test]
    fn vnet_change_serializes_with_receive_configuration_transaction() {
        let socket = Arc::new(socket());
        let transaction = socket.packet_rings.lock();
        let done = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let worker_socket = socket.clone(); let worker_done = done.clone();
        let worker = std::thread::spawn(move || {
            worker_socket.set_packet_vnet_hdr_size(crate::uapi::VIRTIO_NET_HDR_LEN).unwrap();
            worker_done.store(true, Ordering::Release);
        });
        for _ in 0..100 { std::thread::yield_now(); }
        assert!(!done.load(Ordering::Acquire));
        drop(transaction);
        worker.join().unwrap();
        assert!(done.load(Ordering::Acquire));

        let receive = include_str!("packet.rs");
        let lock = receive.find("let mut rings = sock.packet_rings.lock()").unwrap();
        let policy = receive.find("let policy = PacketReceivePolicy").unwrap();
        let commit = receive.find("route_packet_receive_locked(&mut rings").unwrap();
        assert!(lock < policy && policy < commit);
    }
}
