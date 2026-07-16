use super::*;

const RAW: u8 = 3;

fn request() -> PacketRingRequest {
    PacketRingRequest { block_size: 4096, block_nr: 2, frame_size: 256, frame_nr: 32,
        retire_block_timeout: 8, private_size: 16,
        feature_request: crate::uapi::TP_FT_REQ_FILL_RXHASH }
}

fn socket() -> InetSocket {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    socket.set_packet_ring(PacketRingKind::Rx, request()).unwrap();
    socket
}

fn input<'a>(payload: &'a [u8]) -> PacketRingInput<'a> {
    PacketRingInput {
        payload,
        addr: PacketAddr { ifindex: 7, protocol: crate::eth_p::IPV4,
            hatype: crate::uapi::ARPHRD_ETHER, pkttype: crate::uapi::PACKET_HOST,
            halen: 6, addr: [2, 3, 4, 5, 6, 7, 0, 0] },
        aux: PacketAuxData::from_receive(payload.len(), payload.len(), 14,
            crate::uapi::PACKET_HOST, crate::PacketRxMetadata::default(), None, false),
        datagram: false, rxhash: 0x1234_5678,
    }
}

fn route(socket: &InetSocket, payload: &[u8], now_ns: u64) -> bool {
    let value = input(payload);
    let frame = PacketFrame { payload: payload.to_vec(), addr: value.addr, aux: value.aux,
        charge: core::mem::size_of::<PacketFrame>() + payload.len() };
    socket.route_packet_receive(value, frame, usize::MAX, now_ns)
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
fn open_block_and_packet_layout_match_native_v3() {
    let socket = socket();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    let descriptor = read(&pin, 0, 64);
    assert_eq!(u32_at(&descriptor, 0), crate::uapi::TPACKET_V3 as u32);
    assert_eq!(u32_at(&descriptor, 4), 48);
    assert_eq!(u32_at(&descriptor, 8), crate::uapi::TP_STATUS_KERNEL);
    assert_eq!(u32_at(&descriptor, 12), 0);
    assert_eq!(u32_at(&descriptor, 16), 64);
    assert_eq!(u32_at(&descriptor, 20), 64);
    assert_eq!(u64::from_ne_bytes(descriptor[24..32].try_into().unwrap()), 1);

    let payload = [0x5au8; 100];
    assert!(route(&socket, &payload, 9_000_000_123));
    let packet = read(&pin, 64, 184);
    assert_eq!(u32_at(&packet, 0), 184);
    assert_eq!(u32_at(&packet, 4), 9);
    assert_eq!(u32_at(&packet, 8), 123);
    assert_eq!(u32_at(&packet, 12), 100);
    assert_eq!(u32_at(&packet, 16), 100);
    assert_eq!(u32_at(&packet, 20), crate::uapi::TP_STATUS_USER);
    assert_eq!(u16_at(&packet, 24), 82);
    assert_eq!(u16_at(&packet, 26), 96);
    assert_eq!(u32_at(&packet, 28), 0x1234_5678);
    assert_eq!(u16_at(&packet, 48), AF_PACKET);
    assert_eq!(&packet[82..182], &payload);
    assert_eq!(u32_at(&read(&pin, 0, 24), 12), 1);
    assert!(!socket.packet_ring_readable(), "open kernel block is not poll-readable");
}

#[test]
fn timeout_retires_status_last_and_terminates_packet_chain() {
    let socket = socket();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    assert!(route(&socket, &[1u8; 32], 5_000_000_009));
    assert!(socket.service_packet_v3_timer(8_000_000));
    let descriptor = read(&pin, 0, 48);
    assert_eq!(u32_at(&descriptor, 8), crate::uapi::TP_STATUS_USER
        | crate::uapi::TP_STATUS_BLK_TMO);
    assert_eq!(u32_at(&descriptor, 12), 1);
    assert_eq!(u32_at(&read(&pin, 64, 4), 0), 0);
    assert_eq!(u32_at(&descriptor, 40), 5);
    assert_eq!(u32_at(&descriptor, 44), 9);
    assert!(socket.packet_ring_readable());
}

#[test]
fn freeze_drop_release_thaw_and_statistics_follow_block_ownership() {
    let socket = socket();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    assert!(route(&socket, &[1u8; 32], 1));
    assert!(socket.service_packet_v3_timer(8_000_000));
    assert!(route(&socket, &[2u8; 32], 2));
    assert!(socket.service_packet_v3_timer(16_000_000));
    assert!(route(&socket, &[3u8; 32], 3), "drop still wakes packet waiters");
    assert!(pin.release_rx_block(0));
    assert!(route(&socket, &[4u8; 32], 4));
    assert_eq!(socket.take_packet_statistics(), Ok((crate::uapi::TPACKET_V3,
        PacketStatistics { packets: 4, drops: 1, freeze_queue_count: 1 })));
}

#[test]
fn userspace_private_bytes_remain_sticky_across_block_reuse() {
    let socket = socket();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    let sticky = [0xa5u8; 16];
    assert!(pin.write_test(48, &sticky));
    assert!(route(&socket, &[1u8; 32], 1));
    assert!(socket.service_packet_v3_timer(8_000_000));
    assert!(pin.release_rx_block(0));
    assert!(route(&socket, &[2u8; 32], 2));
    assert!(socket.service_packet_v3_timer(16_000_000));
    assert_eq!(&read(&pin, 48, sticky.len()), &sticky);
    assert_eq!(u64::from_ne_bytes(read(&pin, 24, 8).try_into().unwrap()), 3);
}

#[test]
fn large_private_size_matches_linux_kbdq_u16_width() {
    for (private_size, first) in [(65_535, 65_584), (65_536, 48), (65_537, 56)] {
        let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
        socket.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
        let value = PacketRingRequest { block_size: 131_072, block_nr: 1,
            frame_size: 2048, frame_nr: 64, retire_block_timeout: 8,
            private_size, feature_request: 0 };
        socket.set_packet_ring(PacketRingKind::Rx, value).unwrap();
        let pin = socket.packet_ring_mmap(0, 131_072).unwrap();
        let descriptor = read(&pin, 0, 24);
        assert_eq!(u32_at(&descriptor, 16), first);
        assert_eq!(u32_at(&descriptor, 20), first);
    }
}

#[test]
fn rxhash_feature_can_be_disabled_without_changing_v3_layout() {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    let mut value = request(); value.feature_request = 0;
    socket.set_packet_ring(PacketRingKind::Rx, value).unwrap();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    assert!(route(&socket, &[0u8; 32], 1));
    assert_eq!(u32_at(&read(&pin, 64, 36), 28), 0);
}

#[test]
fn exact_block_boundary_retires_empty_block_before_placing_record() {
    let socket = socket();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    let payload = alloc::vec![0x33u8; 3950];
    assert!(route(&socket, &payload, 1));
    let first = read(&pin, 0, 48);
    assert_eq!(u32_at(&first, 8), crate::uapi::TP_STATUS_USER);
    assert_eq!(u32_at(&first, 12), 0);
    let second = read(&pin, 4096, 80);
    assert_eq!(u32_at(&second, 8), crate::uapi::TP_STATUS_KERNEL);
    assert_eq!(u32_at(&second, 12), 1);
    assert_eq!(u32_at(&second, 64), 4032);
}

#[test]
fn multi_packet_chain_uses_aligned_offsets_and_zero_terminator() {
    let socket = socket();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    assert!(route(&socket, &[1u8; 32], 1));
    assert!(route(&socket, &[2u8; 32], 2));
    assert!(socket.service_packet_v3_timer(8_000_000));
    assert_eq!(u32_at(&read(&pin, 64, 4), 0), 120);
    assert_eq!(u32_at(&read(&pin, 184, 4), 0), 0);
    let descriptor = read(&pin, 0, 24);
    assert_eq!(u32_at(&descriptor, 12), 2);
    assert_eq!(u32_at(&descriptor, 20), 304);
}

#[test]
fn raw_loopback_transmit_publishes_one_multicast_record() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let socket = Arc::new(InetSocket::new_packet_in(crate::eth_p::IPV4, RAW, owner.clone()));
    socket.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    socket.set_packet_ring(PacketRingKind::Rx, request()).unwrap();
    register_packet(&socket);
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    let stack = crate::NetStack::new();
    let loopback = Arc::new(crate::LoopbackDev::new());
    let iface = stack.ifaces.register_in_ns(loopback.clone(), owner.id().as_u64());
    let egress = stack.ifaces.acquire_egress_in_ns(iface, owner.id().as_u64()).unwrap();
    let mut frame = alloc::vec![0; 64];
    frame[..6].fill(0xff);
    frame[12..14].copy_from_slice(&crate::eth_p::IPV4.to_be_bytes());

    egress.xmit_raw(&frame).unwrap();
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    stack.drain_loopback_in(&lease, &loopback);
    assert!(socket.service_packet_v3_timer(8_000_000));

    let descriptor = read(&pin, 0, 24);
    assert_eq!(u32_at(&descriptor, 12), 1);
    let packet = read(&pin, 64, 128);
    assert_eq!(u32_at(&packet, 12), frame.len() as u32);
    assert_eq!(packet[58], crate::uapi::PACKET_MULTICAST);
}

#[test]
fn zero_timeout_uses_linux_default_eight_milliseconds() {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    let mut value = request(); value.retire_block_timeout = 0;
    socket.set_packet_ring(PacketRingKind::Rx, value).unwrap();
    assert!(route(&socket, &[1u8; 32], 1));
    assert!(!socket.service_packet_v3_timer(7_999_999));
    assert!(socket.service_packet_v3_timer(8_000_000));
}

#[test]
fn v3_vlan_metadata_uses_variant1_native_fields() {
    let socket = socket();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    let payload = [0u8; 32];
    let mut value = input(&payload);
    value.aux.status |= crate::uapi::TP_STATUS_VLAN_VALID
        | crate::uapi::TP_STATUS_VLAN_TPID_VALID;
    value.aux.vlan_tci = 0x321;
    value.aux.vlan_tpid = crate::eth_p::VLAN_AD;
    let frame = PacketFrame { payload: payload.to_vec(), addr: value.addr, aux: value.aux,
        charge: core::mem::size_of::<PacketFrame>() + payload.len() };
    assert!(socket.route_packet_receive(value, frame, usize::MAX, 1));
    let header = read(&pin, 64, 40);
    assert_ne!(u32_at(&header, 20) & crate::uapi::TP_STATUS_VLAN_VALID, 0);
    assert_eq!(u32_at(&header, 32), 0x321);
    assert_eq!(u16_at(&header, 36), crate::eth_p::VLAN_AD);
}

#[test]
fn final_release_prevents_timer_retirement_while_mmap_keeps_pages_alive() {
    let socket = Arc::new(socket());
    register_packet(&socket);
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    assert!(route(&socket, &[1u8; 32], 1));
    socket.release_file();
    service_packet_ring_timers(8_000_000);
    assert_eq!(u32_at(&read(&pin, 0, 16), 8), crate::uapi::TP_STATUS_KERNEL);
}
