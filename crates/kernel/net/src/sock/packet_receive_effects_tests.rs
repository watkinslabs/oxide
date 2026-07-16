use super::*;

const RAW: u8 = 3;
const SOFTWARE: i32 = 1 << 4;
const RAW_HARDWARE: i32 = 1 << 6;

fn request(frame_size: u32) -> PacketRingRequest {
    PacketRingRequest { block_size: 4096, block_nr: 1, frame_size,
        frame_nr: 4096 / frame_size, ..PacketRingRequest::default() }
}

fn input<'a>(payload: &'a [u8], aux: PacketAuxData) -> PacketRingInput<'a> {
    PacketRingInput {
        payload,
        addr: PacketAddr { ifindex: 3, protocol: crate::eth_p::IPV4,
            hatype: crate::uapi::ARPHRD_ETHER, pkttype: crate::uapi::PACKET_HOST,
            halen: 6, addr: [2, 3, 4, 5, 6, 7, 0, 0] },
        aux, datagram: false, rxhash: 0,
    }
}

fn aux(payload: &[u8]) -> PacketAuxData {
    PacketAuxData::from_receive(payload.len(), payload.len(), 14,
        crate::uapi::PACKET_HOST, crate::PacketRxMetadata::default(), None, false)
}

fn frame(payload: &[u8], aux: PacketAuxData) -> PacketFrame {
    PacketFrame { payload: payload.to_vec(), addr: input(payload, aux).addr, aux,
        charge: core::mem::size_of::<PacketFrame>() + payload.len() }
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
fn vnet_header_encodes_metadata_and_zeroes_num_buffers() {
    let mut packet = [0u8; 54]; packet[14] = 0x60;
    let metadata = crate::PacketRxMetadata {
        checksum: crate::PacketChecksum::Partial,
        virtio: crate::PacketVirtioMetadata { gso_type: 4, header_len: 54,
            gso_size: 1200, checksum_start: 34, checksum_offset: 16 },
        ..crate::PacketRxMetadata::default()
    };
    let header = receive_vnet_header(metadata).unwrap();
    assert_eq!(header[0], 1);
    assert_eq!(header[1], 4);
    assert_eq!(u16::from_le_bytes(header[2..4].try_into().unwrap()), 54);
    assert_eq!(u16::from_le_bytes(header[4..6].try_into().unwrap()), 1200);
    assert_eq!(u16::from_le_bytes(header[6..8].try_into().unwrap()), 34);
    assert_eq!(u16::from_le_bytes(header[8..10].try_into().unwrap()), 16);
    assert_eq!(&header[10..12], &[0; 2]);
}

#[test]
fn queued_raw_receive_places_vnet_header_immediately_before_packet() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let socket = Arc::new(InetSocket::new_packet_in(crate::eth_p::ALL, RAW, owner.clone()));
    socket.set_packet_vnet_hdr_size(10).unwrap();
    register_packet(&socket);
    let stack = crate::NetStack::new();
    let loopback = Arc::new(crate::LoopbackDev::new());
    let iface = stack.ifaces.register_in_ns(loopback, owner.id().as_u64());
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    let packet = [0x45u8, 0, 0, 20];
    deliver_packet_loopback_in(&lease, &packet, crate::eth_p::IPV4);
    let frames = socket.take_packet_test_frames().unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(&frames[0].payload[..10], &[0; 10]);
    assert_eq!(&frames[0].payload[10..], &packet);
    assert_eq!(frames[0].aux.status & (TP_STATUS_TS_SOFTWARE
        | TP_STATUS_TS_RAW_HARDWARE), 0);
    assert_eq!(frames[0].aux.timestamp_status, 0);
    assert!(frames[0].aux.timestamp_ns.is_some());
    assert_eq!(validate_vnet_receive_capacity(10, 9), Err(crate::NetError::Einval));
    assert_eq!(validate_vnet_receive_capacity(10, 10), Ok(()));
}

#[test]
fn v1_v2_vnet_offsets_and_copy_admission_are_exact() {
    for (version, vnet) in [(crate::uapi::TPACKET_V1, 10u8),
                            (crate::uapi::TPACKET_V2, 12u8)] {
        let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
        socket.set_packet_version(version).unwrap();
        socket.set_packet_ring(PacketRingKind::Rx, request(128)).unwrap();
        let pin = socket.packet_ring_mmap(0, 4096).unwrap();
        let payload = [0x5au8; 100];
        let captured = &payload[..80];
        let mut value = PacketAuxData::from_receive(payload.len(), captured.len(), 14,
            crate::uapi::PACKET_HOST, crate::PacketRxMetadata::default(), None, false);
        value.vnet_hdr_size = vnet;
        value.status |= crate::uapi::TP_STATUS_CSUMNOTREADY;
        value.vnet_header = receive_vnet_header(crate::PacketRxMetadata {
            checksum: crate::PacketChecksum::Partial, ..crate::PacketRxMetadata::default()
        }).unwrap();
        value.copy_thresh = true;
        let queued = frame(captured, value);
        assert!(socket.route_packet_receive_full(input(captured, value), queued, &payload,
            usize::MAX, 1));
        let bytes = read(&pin, 0, 128);
        let status = if version == crate::uapi::TPACKET_V1 {
            u64::from_ne_bytes(bytes[0..8].try_into().unwrap()) as u32
        } else { u32_at(&bytes, 0) };
        let mac = if version == crate::uapi::TPACKET_V1 { u16_at(&bytes, 16) }
            else { u16_at(&bytes, 12) };
        let net = if version == crate::uapi::TPACKET_V1 { u16_at(&bytes, 18) }
            else { u16_at(&bytes, 14) };
        assert_eq!(mac, 66 + vnet as u16);
        assert_eq!(net, 80 + vnet as u16);
        assert_eq!(&bytes[mac as usize - vnet as usize..mac as usize - VNET_HDR_SIZE],
            &alloc::vec![0; vnet as usize - VNET_HDR_SIZE]);
        assert_eq!(bytes[mac as usize - VNET_HDR_SIZE], 1,
            "base header starts ten bytes before packet data");
        assert_ne!(status & TP_STATUS_COPY, 0);
        let copies = socket.take_packet_test_frames().unwrap();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].payload.len(), vnet as usize + payload.len());
        assert_eq!(copies[0].payload[0], 1, "queue emits the full selected header first");
        assert_eq!(&copies[0].payload[vnet as usize..], &payload);
    }
}

#[test]
fn v3_vnet_uses_selected_twelve_byte_region_and_keeps_packet_lengths() {
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    let v3 = PacketRingRequest { block_size: 4096, block_nr: 1, frame_size: 128,
        frame_nr: 32, retire_block_timeout: 8, ..PacketRingRequest::default() };
    socket.set_packet_ring(PacketRingKind::Rx, v3).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let payload = [0x5au8; 64];
    let mut value = aux(&payload);
    value.vnet_hdr_size = super::packet_virtio::VNET_MRG_HEADER_LEN as u8;
    value.status |= crate::uapi::TP_STATUS_CSUMNOTREADY;
    value.vnet_header = receive_vnet_header(crate::PacketRxMetadata {
        checksum: crate::PacketChecksum::Partial, ..crate::PacketRxMetadata::default()
    }).unwrap();
    assert!(socket.route_packet_receive(input(&payload, value), frame(&payload, value),
        usize::MAX, 1));

    let record = read(&pin, 48, 192);
    let mac = u16_at(&record, 24) as usize;
    let net = u16_at(&record, 26) as usize;
    assert_eq!(u32_at(&record, 0), 160);
    assert_eq!(u32_at(&record, 12), payload.len() as u32);
    assert_eq!(u32_at(&record, 16), payload.len() as u32);
    assert_eq!((mac, net), (94, 108));
    assert_eq!(&record[mac - 12..mac - VNET_HDR_SIZE], &[0; 2]);
    assert_eq!(&record[mac - VNET_HDR_SIZE..mac], &value.vnet_header[..VNET_HDR_SIZE]);
    assert_eq!(&record[mac..mac + payload.len()], &payload);
}

#[test]
fn copy_status_requires_queue_admission_and_v3_never_copies() {
    let payload = [0x33u8; 100];
    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_ring(PacketRingKind::Rx, request(128)).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let mut value = aux(&payload); value.copy_thresh = true;
    assert!(socket.route_packet_receive(input(&payload, value), frame(&payload, value), 0, 1));
    let status = u64::from_ne_bytes(read(&pin, 0, 8).try_into().unwrap()) as u32;
    assert_eq!(status & TP_STATUS_COPY, 0);
    assert!(socket.take_packet_test_frames().unwrap().is_empty());

    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    let v3 = PacketRingRequest { block_size: 4096, block_nr: 1, frame_size: 128,
        frame_nr: 32, retire_block_timeout: 8, ..PacketRingRequest::default() };
    socket.set_packet_ring(PacketRingKind::Rx, v3).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    assert!(socket.route_packet_receive(input(&payload, value), frame(&payload, value),
        usize::MAX, 1));
    assert_eq!(u32_at(&read(&pin, 48, 24), 20) & TP_STATUS_COPY, 0);
    assert!(socket.take_packet_test_frames().unwrap().is_empty());
}

#[test]
fn timestamp_selection_prefers_requested_sources_and_falls_back_to_software() {
    let metadata = crate::PacketRxMetadata { software_timestamp_ns: Some(11),
        raw_hardware_timestamp_ns: Some(22), ..crate::PacketRxMetadata::default() };
    assert_eq!(receive_timestamp(metadata, RAW_HARDWARE | SOFTWARE, 33),
        (22, TP_STATUS_TS_RAW_HARDWARE));
    assert_eq!(receive_timestamp(metadata, SOFTWARE, 33),
        (11, TP_STATUS_TS_SOFTWARE));
    let none = crate::PacketRxMetadata::default();
    assert_eq!(receive_timestamp(none, RAW_HARDWARE, 33), (33, 0));
}

#[test]
fn ring_timestamp_precision_is_v1_usec_and_v2_v3_nsec() {
    let payload = [0u8; 32];
    for version in [crate::uapi::TPACKET_V1, crate::uapi::TPACKET_V2] {
        let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
        socket.set_packet_version(version).unwrap();
        socket.set_packet_ring(PacketRingKind::Rx, request(256)).unwrap();
        let pin = socket.packet_ring_mmap(0, 4096).unwrap();
        let mut value = aux(&payload);
        value.timestamp_ns = Some(7_123_456_789);
        value.timestamp_status = TP_STATUS_TS_RAW_HARDWARE;
        assert_eq!(socket.publish_packet_ring_v12(input(&payload, value), 1), Some(true));
        let bytes = read(&pin, 0, 32);
        let subsec = if version == crate::uapi::TPACKET_V1 { u32_at(&bytes, 24) }
            else { u32_at(&bytes, 20) };
        assert_eq!(subsec, if version == crate::uapi::TPACKET_V1 { 123_456 } else { 123_456_789 });
    }

    let socket = InetSocket::new_packet(crate::eth_p::ALL, RAW);
    socket.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    let v3 = PacketRingRequest { block_size: 4096, block_nr: 1, frame_size: 256,
        frame_nr: 16, retire_block_timeout: 8, ..PacketRingRequest::default() };
    socket.set_packet_ring(PacketRingKind::Rx, v3).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let mut value = aux(&payload); value.timestamp_ns = Some(7_123_456_789);
    assert!(socket.route_packet_receive(input(&payload, value), frame(&payload, value),
        usize::MAX, 1));
    let bytes = read(&pin, 48, 16);
    assert_eq!(u32_at(&bytes, 4), 7);
    assert_eq!(u32_at(&bytes, 8), 123_456_789);
}
