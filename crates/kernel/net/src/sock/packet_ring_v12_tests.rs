use super::*;

const RAW: u8 = 3;
const DGRAM: u8 = 2;

fn request() -> PacketRingRequest {
    PacketRingRequest { block_size: 4096, block_nr: 1, frame_size: 256, frame_nr: 16,
        ..PacketRingRequest::default() }
}

fn input<'a>(payload: &'a [u8], datagram: bool) -> PacketRingInput<'a> {
    PacketRingInput {
        payload,
        addr: PacketAddr { ifindex: 9, protocol: crate::eth_p::IPV4,
            hatype: crate::uapi::ARPHRD_ETHER, pkttype: crate::uapi::PACKET_HOST,
            halen: 6, addr: [2, 3, 4, 5, 6, 7, 0, 0] },
        aux: PacketAuxData::from_receive(payload.len(), payload.len(),
            if datagram { 0 } else { 14 }, crate::uapi::PACKET_HOST,
            crate::PacketRxMetadata::default(), None, datagram),
        datagram,
        rxhash: 0x1234_5678,
    }
}

fn read(pin: &PacketRingMmap, off: u64, len: usize) -> Vec<u8> {
    let mut bytes = alloc::vec![0; len];
    assert!(pin.read(off, &mut bytes));
    bytes
}

fn u16_at(bytes: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes(bytes[off..off + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap())
}

#[test]
fn v1_raw_frame_publishes_status_last_layout_payload_sockaddr_and_timestamp() {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_ring(PacketRingKind::Rx, request()).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let payload = alloc::vec![0x5a; 220];
    assert_eq!(socket.publish_packet_ring_v12(input(&payload, false),
        7 * 1_000_000_000 + 123_456_789), Some(true));
    let frame = read(&pin, 0, 256);
    assert_eq!(u64::from_ne_bytes(frame[0..8].try_into().unwrap()),
        crate::uapi::TP_STATUS_USER as u64);
    assert_eq!(u32_at(&frame, 8), 220);
    assert_eq!(u32_at(&frame, 12), 190, "snaplen clamps to frame end");
    assert_eq!(u16_at(&frame, 16), 66);
    assert_eq!(u16_at(&frame, 18), 80);
    assert_eq!(u32_at(&frame, 20), 7);
    assert_eq!(u32_at(&frame, 24), 123_456);
    assert_eq!(u16_at(&frame, 32), AF_PACKET);
    assert_eq!(&frame[34..36], &crate::eth_p::IPV4.to_be_bytes());
    assert_eq!(u32_at(&frame, 36), 9);
    assert_eq!(u16_at(&frame, 40), crate::uapi::ARPHRD_ETHER);
    assert_eq!(&frame[66..256], &payload[..190]);
    assert!(socket.packet_ring_readable());
    assert!(pin.release_rx_frame(0));
    assert!(!socket.packet_ring_readable());
}

#[test]
fn v2_datagram_encodes_vlan_checksum_offsets_and_nanoseconds() {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, DGRAM);
    socket.set_packet_version(crate::uapi::TPACKET_V2).unwrap();
    socket.set_packet_reserve(8).unwrap();
    socket.set_packet_ring(PacketRingKind::Rx, request()).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let payload = [0x45, 1, 2, 3];
    let mut value = input(&payload, true);
    value.aux.status |= crate::uapi::TP_STATUS_CSUM_VALID
        | crate::uapi::TP_STATUS_VLAN_VALID | crate::uapi::TP_STATUS_VLAN_TPID_VALID;
    value.aux.vlan_tci = 0x321;
    value.aux.vlan_tpid = crate::eth_p::VLAN_AD;
    assert_eq!(socket.publish_packet_ring_v12(value, 11_000_000_099), Some(true));
    let frame = read(&pin, 0, 256);
    assert_eq!(u32_at(&frame, 0), crate::uapi::TP_STATUS_USER
        | crate::uapi::TP_STATUS_CSUM_VALID | crate::uapi::TP_STATUS_VLAN_VALID
        | crate::uapi::TP_STATUS_VLAN_TPID_VALID);
    assert_eq!(u16_at(&frame, 12), 88);
    assert_eq!(u16_at(&frame, 14), 88);
    assert_eq!(u32_at(&frame, 16), 11);
    assert_eq!(u32_at(&frame, 20), 99);
    assert_eq!(u16_at(&frame, 24), 0x321);
    assert_eq!(u16_at(&frame, 26), crate::eth_p::VLAN_AD);
    assert_eq!(&frame[28..32], &[0; 4]);
    assert_eq!(&frame[88..92], &payload);
}

#[test]
fn ring_wrap_pressure_drop_losing_and_userspace_release_are_exact() {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_ring(PacketRingKind::Rx, request()).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let payload = [0xabu8; 32];
    assert_eq!(socket.packet_ring_room(), Some(PacketRoom::Normal));
    for _ in 0..12 { assert_eq!(socket.publish_packet_ring_v12(input(&payload, false), 1), Some(true)); }
    assert_eq!(socket.packet_ring_room(), Some(PacketRoom::Low));
    for _ in 12..16 { assert_eq!(socket.publish_packet_ring_v12(input(&payload, false), 1), Some(true)); }
    assert_eq!(socket.packet_ring_room(), Some(PacketRoom::None));
    assert_eq!(socket.publish_packet_ring_v12(input(&payload, false), 1), Some(false));
    assert_eq!(socket.take_packet_statistics(), Ok((crate::uapi::TPACKET_V1,
        PacketStatistics { packets: 17, drops: 1, freeze_queue_count: 0 })));
    assert!(pin.release_rx_frame(0));
    assert_eq!(socket.publish_packet_ring_v12(input(&payload, false), 2), Some(true));
    let frame = read(&pin, 0, 32);
    assert_eq!(u64::from_ne_bytes(frame[0..8].try_into().unwrap()),
        crate::uapi::TP_STATUS_USER as u64,
        "statistics read clears LOSING before reused frame publication");

    assert_eq!(socket.publish_packet_ring_v12(input(&payload, false), 3), Some(false));
    assert!(pin.release_rx_frame(1));
    assert_eq!(socket.publish_packet_ring_v12(input(&payload, false), 4), Some(true));
    let reused = read(&pin, 256, 8);
    assert_ne!(u64::from_ne_bytes(reused.try_into().unwrap())
        & crate::uapi::TP_STATUS_LOSING as u64, 0);
}

#[test]
fn v1_suppresses_v2_only_vlan_status() {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_ring(PacketRingKind::Rx, request()).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let payload = [0u8; 32];
    let mut value = input(&payload, false);
    value.aux.status |= crate::uapi::TP_STATUS_VLAN_VALID
        | crate::uapi::TP_STATUS_VLAN_TPID_VALID;
    assert_eq!(socket.publish_packet_ring_v12(value, 0), Some(true));
    let status = u64::from_ne_bytes(read(&pin, 0, 8).try_into().unwrap()) as u32;
    assert_eq!(status & (crate::uapi::TP_STATUS_VLAN_VALID
        | crate::uapi::TP_STATUS_VLAN_TPID_VALID), 0);
}

#[test]
fn receive_delivery_uses_ring_as_the_only_canonical_destination() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let socket = Arc::new(InetSocket::new_packet_in(crate::eth_p::ALL, RAW, owner.clone()));
    register_packet(&socket);
    socket.set_packet_ring(PacketRingKind::Rx, request()).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let stack = crate::NetStack::new();
    let loopback = Arc::new(crate::LoopbackDev::new());
    let iface = stack.ifaces.register_in_ns(loopback, owner.id().as_u64());
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    let payload = [0x45u8, 0, 0, 20];
    deliver_packet_loopback_in(&lease, &payload, crate::eth_p::IPV4);
    assert!(socket.take_packet_test_frames().unwrap().is_empty(),
        "ring publication must not duplicate into the legacy receive queue");
    assert_eq!(&read(&pin, 80, payload.len()), &payload);
    assert_eq!(socket.take_packet_statistics(), Ok((crate::uapi::TPACKET_V1,
        PacketStatistics { packets: 1, drops: 0, freeze_queue_count: 0 })));
}

#[test]
fn minimum_linux_frame_publishes_zero_snaplen_when_mac_starts_past_end() {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    let minimum = PacketRingRequest { block_size: 4096, block_nr: 1,
        frame_size: 64, frame_nr: 64, ..PacketRingRequest::default() };
    socket.set_packet_ring(PacketRingKind::Rx, minimum).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let payload = [0u8; 32];
    assert_eq!(socket.publish_packet_ring_v12(input(&payload, false), 0), Some(true));
    let frame = read(&pin, 0, 32);
    assert_eq!(u32_at(&frame, 12), 0);
    assert_eq!(u16_at(&frame, 16), 66);
    assert_eq!(u64::from_ne_bytes(frame[0..8].try_into().unwrap()),
        crate::uapi::TP_STATUS_USER as u64);
}
