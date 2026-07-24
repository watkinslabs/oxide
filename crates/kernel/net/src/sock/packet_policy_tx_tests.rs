use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const RAW: u8 = 3;
const GSO_ECN: u8 = 0x80;

struct PolicyDev {
    queued: AtomicUsize,
    direct: AtomicUsize,
    frames: Mutex<Vec<Vec<u8>>>,
}

impl PolicyDev {
    fn new() -> Self { Self { queued: AtomicUsize::new(0), direct: AtomicUsize::new(0),
        frames: Mutex::new(Vec::new()) } }
}

impl crate::NetDev for PolicyDev {
    fn name(&self) -> &str { "policy0" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr([2, 3, 4, 5, 6, 7]) }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, packet: crate::Pkt) -> crate::NetResult<()> { self.xmit_raw(packet.data()) }
    fn xmit_raw(&self, frame: &[u8]) -> crate::NetResult<()> {
        self.queued.fetch_add(1, Ordering::Relaxed);
        self.frames.lock().unwrap().push(frame.to_vec()); Ok(())
    }
    fn xmit_raw_direct(&self, frame: &[u8]) -> crate::NetResult<()> {
        self.direct.fetch_add(1, Ordering::Relaxed);
        self.frames.lock().unwrap().push(frame.to_vec()); Ok(())
    }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
}

fn socket() -> (Arc<InetSocket>, Arc<PolicyDev>) {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let device = Arc::new(PolicyDev::new());
    let iface = stack().ifaces.register_in_ns(device.clone(), owner.id().as_u64());
    // Interfaces register admin-DOWN (Linux); AF_PACKET TX needs IFF_UP, so open
    // it here the way `ip link set up` would before sending.
    {
        let rtnl = stack().rtnl_lock();
        stack().ifaces.set_iface_flags_in_ns(&rtnl, iface, owner.id().as_u64(),
            crate::netdev::iff::IFF_UP, crate::netdev::iff::IFF_UP).unwrap();
    }
    let socket = Arc::new(InetSocket::new_packet_in(crate::eth_p::IPV4, RAW, owner));
    if let SockKind::Packet { ifindex, .. } = &*socket.kind.lock() {
        ifindex.store(iface.raw(), Ordering::Release);
    }
    (socket, device)
}

fn tcp_frame(payload: usize) -> Vec<u8> {
    let mut frame = alloc::vec![0u8; 14 + 20 + 20 + payload];
    frame[0..6].fill(0xff); frame[6..12].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    frame[12..14].copy_from_slice(&crate::eth_p::IPV4.to_be_bytes());
    frame[14] = 0x45; frame[23] = 6;
    frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
    frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
    frame[46] = 0x50; frame[47] = 0x19;
    frame
}

fn vnet(gso: u8, size: u16) -> Vec<u8> {
    super::packet_virtio::VirtioHeader { flags: 1, gso_type: gso, hdr_len: 54,
        gso_size: size, csum_start: 34, csum_offset: 16 }
        .encode(super::packet_virtio::VNET_HEADER_LEN)
}

#[test]
fn ordinary_vnet_send_returns_header_length_and_selects_qdisc_path() {
    let (socket, device) = socket();
    socket.set_packet_vnet_hdr_size(super::packet_virtio::VNET_HEADER_LEN).unwrap();
    let frame = tcp_frame(16);
    let mut input = vnet(0, 0); input.extend_from_slice(&frame);
    assert_eq!(send_packet(&socket, &input, None), Ok(input.len()));
    assert_eq!(device.queued.load(Ordering::Acquire), 1);
    assert_eq!(device.direct.load(Ordering::Acquire), 0);
    let sent = device.frames.lock().unwrap()[0].clone();
    assert_eq!(sent.len(), frame.len());
    assert_eq!(&sent[..50], &frame[..50]);
    assert_eq!(&sent[52..], &frame[52..]);
    assert_ne!(&sent[50..52], &[0, 0]);
    socket.set_packet_qdisc_bypass(true).unwrap();
    assert_eq!(send_packet(&socket, &input, None), Ok(input.len()));
    assert_eq!(device.direct.load(Ordering::Acquire), 1);
}

#[test]
fn virtio_tcp_gso_uses_software_segments_when_device_has_no_offload() {
    let (socket, device) = socket();
    socket.set_packet_vnet_hdr_size(super::packet_virtio::VNET_HEADER_LEN).unwrap();
    let body = tcp_frame(2000);
    let mut input = vnet(1, 1000); input.extend_from_slice(&body);
    assert_eq!(send_packet(&socket, &input, None), Ok(input.len()));
    let frames = device.frames.lock().unwrap();
    assert_eq!(frames.len(), 2);
    assert!(frames.iter().all(|frame| frame.len() <= 1518));
    assert_eq!(u32::from_be_bytes(frames[1][38..42].try_into().unwrap()), 1000);
    assert_eq!(frames[0][47] & 0x09, 0);
    assert_eq!(frames[1][47] & 0x09, 0x09);
}

fn request() -> PacketRingRequest {
    PacketRingRequest { block_size: 4096, block_nr: 1, frame_size: 1024, frame_nr: 4,
        ..PacketRingRequest::default() }
}

fn tx_fields(version: u8) -> (u64, u64, u64) {
    match version {
        crate::uapi::TPACKET_V1 => (8, 16, crate::uapi::TPACKET_V1_HEADER_LEN as u64),
        crate::uapi::TPACKET_V2 => (4, 12, crate::uapi::TPACKET_V2_HEADER_LEN as u64),
        crate::uapi::TPACKET_V3 => (16, 24, crate::uapi::TPACKET_V3_HEADER_LEN as u64),
        _ => unreachable!(),
    }
}

#[test]
fn vnet_tx_ring_tp_len_includes_header_but_completion_counts_body_for_all_versions() {
    const EXPLICIT: u64 = 96;
    for version in [crate::uapi::TPACKET_V1, crate::uapi::TPACKET_V2,
                    crate::uapi::TPACKET_V3] {
        for has_offset in [false, true] {
            let (socket, device) = socket();
            socket.set_packet_vnet_hdr_size(super::packet_virtio::VNET_MRG_HEADER_LEN).unwrap();
            socket.set_packet_tx_has_off(has_offset).unwrap();
            socket.set_packet_version(version).unwrap();
            socket.set_packet_ring(PacketRingKind::Tx, request()).unwrap();
            let pin = socket.packet_ring_mmap(0, 4096).unwrap();
            let ring = pin.tx_test().unwrap();
            let frame = tcp_frame(8);
            let mut input = super::packet_virtio::VirtioHeader::default()
                .encode(super::packet_virtio::VNET_MRG_HEADER_LEN);
            input.extend_from_slice(&frame);
            let base = ring.frame_offset(0).unwrap();
            let (length_field, mac_field, native) = tx_fields(version);
            if version == crate::uapi::TPACKET_V3 {
                assert!(ring.write(base, &0u32.to_ne_bytes()));
            }
            assert!(ring.write(base + length_field, &(input.len() as u32).to_ne_bytes()));
            let data = if has_offset {
                assert!(ring.write(base + native, &[0xff; 12]));
                assert!(ring.write(base + mac_field, &(EXPLICIT as u16).to_ne_bytes()));
                EXPLICIT
            } else { native };
            assert!(ring.write(base + data, &input));
            assert!(ring.publish_status(0, crate::uapi::TP_STATUS_SEND_REQUEST));
            assert_eq!(socket.kick_packet_tx_ring(None), Ok(frame.len()));
            assert_eq!(device.frames.lock().unwrap().as_slice(), &[frame]);
            assert_eq!(ring.status(0), Some(crate::uapi::TP_STATUS_AVAILABLE));
            assert_eq!(ring.head(), 1);
        }
    }
}

#[test]
fn tx_has_off_selects_native_mac_offsets_for_every_version() {
    for version in [crate::uapi::TPACKET_V1, crate::uapi::TPACKET_V2,
                    crate::uapi::TPACKET_V3] {
        let (socket, device) = socket();
        socket.set_packet_tx_has_off(true).unwrap();
        socket.set_packet_qdisc_bypass(true).unwrap();
        socket.set_packet_version(version).unwrap();
        socket.set_packet_ring(PacketRingKind::Tx, request()).unwrap();
        let pin = socket.packet_ring_mmap(0, 4096).unwrap();
        let ring = pin.tx_test().unwrap();
        let frame = tcp_frame(8);
        let base = ring.frame_offset(0).unwrap();
        if version == crate::uapi::TPACKET_V3 {
            assert!(ring.write(base, &0u32.to_ne_bytes()));
            assert!(ring.write(base + 16, &(frame.len() as u32).to_ne_bytes()));
            assert!(ring.write(base + 24, &64u16.to_ne_bytes()));
        } else if version == crate::uapi::TPACKET_V2 {
            assert!(ring.write(base + 4, &(frame.len() as u32).to_ne_bytes()));
            assert!(ring.write(base + 12, &64u16.to_ne_bytes()));
        } else {
            assert!(ring.write(base + 8, &(frame.len() as u32).to_ne_bytes()));
            assert!(ring.write(base + 16, &64u16.to_ne_bytes()));
        }
        assert!(ring.write(base + 64, &frame));
        assert!(ring.publish_status(0, crate::uapi::TP_STATUS_SEND_REQUEST));
        assert_eq!(socket.kick_packet_tx_ring(None), Ok(frame.len()));
        assert_eq!(device.frames.lock().unwrap()[0], frame);
        assert_eq!(device.direct.load(Ordering::Acquire), 1);
    }
}

#[test]
fn tx_has_off_rejects_offsets_below_native_header_without_advancing() {
    let (socket, device) = socket();
    socket.set_packet_tx_has_off(true).unwrap();
    socket.set_packet_ring(PacketRingKind::Tx, request()).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let ring = pin.tx_test().unwrap();
    let frame = tcp_frame(8);
    assert!(ring.write(8, &(frame.len() as u32).to_ne_bytes()));
    assert!(ring.write(16, &16u16.to_ne_bytes()));
    assert!(ring.write(16, &frame));
    assert!(ring.publish_status(0, crate::uapi::TP_STATUS_SEND_REQUEST));
    assert_eq!(socket.kick_packet_tx_ring(None), Err(crate::NetError::Einval));
    assert_eq!(ring.status(0), Some(crate::uapi::TP_STATUS_WRONG_FORMAT));
    assert_eq!(ring.head(), 0);
    assert!(device.frames.lock().unwrap().is_empty());
}

#[test]
fn malformed_vnet_tx_ring_obeys_loss_and_wrong_format_policy() {
    for loss in [false, true] {
        let (socket, device) = socket();
        socket.set_packet_vnet_hdr_size(super::packet_virtio::VNET_HEADER_LEN).unwrap();
        socket.set_packet_loss(loss).unwrap();
        socket.set_packet_ring(PacketRingKind::Tx, request()).unwrap();
        let pin = socket.packet_ring_mmap(0, 4096).unwrap();
        let ring = pin.tx_test().unwrap();
        let mut input = super::packet_virtio::VirtioHeader {
            gso_type: GSO_ECN, ..super::packet_virtio::VirtioHeader::default()
        }.encode(super::packet_virtio::VNET_HEADER_LEN);
        input.extend_from_slice(&tcp_frame(8));
        assert!(ring.write(8, &(input.len() as u32).to_ne_bytes()));
        assert!(ring.write(crate::uapi::TPACKET_V1_HEADER_LEN as u64, &input));
        assert!(ring.publish_status(0, crate::uapi::TP_STATUS_SEND_REQUEST));
        if loss {
            assert_eq!(socket.kick_packet_tx_ring(None), Ok(0));
            assert_eq!(ring.status(0), Some(crate::uapi::TP_STATUS_AVAILABLE));
            assert_eq!(ring.head(), 1);
        } else {
            assert_eq!(socket.kick_packet_tx_ring(None), Err(crate::NetError::Einval));
            assert_eq!(ring.status(0), Some(crate::uapi::TP_STATUS_WRONG_FORMAT));
            assert_eq!(ring.head(), 0);
        }
        assert!(device.frames.lock().unwrap().is_empty());
    }
}
