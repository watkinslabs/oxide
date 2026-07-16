use super::*;

const RAW: u8 = 3;

fn socket() -> InetSocket { InetSocket::new_packet(crate::eth_p::ALL, RAW) }

fn request(block_nr: u32) -> PacketRingRequest {
    PacketRingRequest {
        block_size: 4096,
        block_nr,
        frame_size: 256,
        frame_nr: 16 * block_nr,
        ..PacketRingRequest::default()
    }
}

#[test]
fn valid_v1_ring_maps_exact_owned_pages() {
    let socket = socket();
    socket.set_packet_ring(PacketRingKind::Rx, request(2)).unwrap();
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    assert_eq!(pin.len(), 8192);
    assert!(pin.frame(0).is_some());
    assert_eq!(pin.frame(0).unwrap() + 4096, pin.frame(4096).unwrap());
    assert_eq!(pin.frame(1), None);
    assert_eq!(pin.frame(8192), None);
}

#[test]
fn combined_mapping_orders_rx_before_tx_and_requires_exact_shape() {
    let socket = socket();
    socket.set_packet_ring(PacketRingKind::Rx, request(1)).unwrap();
    socket.set_packet_ring(PacketRingKind::Tx, request(1)).unwrap();
    assert_eq!(socket.packet_ring_mmap(4096, 8192).err(), Some(crate::NetError::Einval));
    assert_eq!(socket.packet_ring_mmap(0, 4096).err(), Some(crate::NetError::Einval));
    let pin = socket.packet_ring_mmap(0, 8192).unwrap();
    assert_ne!(pin.frame(0), pin.frame(4096));
}

#[test]
fn configured_or_mapped_rings_enforce_linux_busy_rules() {
    let socket = socket();
    socket.set_packet_reserve(32).unwrap();
    socket.set_packet_ring(PacketRingKind::Rx, request(1)).unwrap();
    assert_eq!(socket.set_packet_version(crate::uapi::TPACKET_V2), Err(crate::NetError::Ebusy));
    assert_eq!(socket.set_packet_reserve(0), Err(crate::NetError::Ebusy));
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, request(1)), Err(crate::NetError::Ebusy));
    let mut invalid = request(1); invalid.block_size = 1;
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, invalid), Err(crate::NetError::Ebusy));
    assert_eq!(socket.set_packet_ring_versioned(
        PacketRingKind::Tx, crate::uapi::TPACKET_V2, request(1)), Err(crate::NetError::Einval));
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, PacketRingRequest::default()),
        Err(crate::NetError::Ebusy));
    drop(pin);
    socket.set_packet_ring(PacketRingKind::Rx, PacketRingRequest::default()).unwrap();
    assert_eq!(socket.packet_ring_mmap(0, 0).err(), Some(crate::NetError::Einval));
}

#[test]
fn layout_validation_rejects_non_linux_shapes() {
    let socket = socket();
    let mut value = request(1);
    value.block_size = 4095;
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, value), Err(crate::NetError::Einval));
    value = request(1); value.block_size = i32::MAX as u32 + 1;
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, value), Err(crate::NetError::Einval));
    value = request(1); value.frame_size = 250;
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, value), Err(crate::NetError::Einval));
    value = request(1); value.frame_nr = 15;
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, value), Err(crate::NetError::Einval));
    value = PacketRingRequest { block_size: 4096, block_nr: 1,
        frame_size: 4096, frame_nr: 2, ..PacketRingRequest::default() };
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, value), Err(crate::NetError::Einval));
    value = PacketRingRequest { frame_nr: 1, ..PacketRingRequest::default() };
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, value), Err(crate::NetError::Einval));
}

#[test]
fn reserve_participates_in_minimum_frame_validation() {
    let socket = socket();
    socket.set_packet_reserve(205).unwrap();
    assert_eq!(socket.set_packet_ring(PacketRingKind::Rx, request(1)), Err(crate::NetError::Einval));
    assert_eq!(socket.set_packet_reserve(i32::MAX as u32 + 1), Err(crate::NetError::Einval));
}

#[test]
fn v3_validates_private_block_space_and_tx_extension_fields() {
    let rx = socket();
    rx.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    let mut value = request(1);
    value.private_size = 4000;
    assert_eq!(rx.set_packet_ring(PacketRingKind::Rx, value), Err(crate::NetError::Einval));

    let tx = socket();
    tx.set_packet_version(crate::uapi::TPACKET_V3).unwrap();
    value = request(1); value.retire_block_timeout = 1;
    assert_eq!(tx.set_packet_ring(PacketRingKind::Tx, value), Err(crate::NetError::Einval));
    value = request(1); value.private_size = 1;
    assert_eq!(tx.set_packet_ring(PacketRingKind::Tx, value), Err(crate::NetError::Einval));
    value = request(1); value.feature_request = 1;
    assert_eq!(tx.set_packet_ring(PacketRingKind::Tx, value), Err(crate::NetError::Einval));
}

#[test]
fn mmap_pin_survives_final_socket_release() {
    let socket = socket();
    socket.set_packet_ring(PacketRingKind::Rx, request(1)).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    let frame = pin.frame(0);
    socket.release_file();
    assert_eq!(pin.frame(0), frame);
    assert_eq!(socket.packet_ring_mmap(0, 4096).err(), Some(crate::NetError::Einval));
}

#[test]
fn packet_header_lengths_match_native_linux_structs() {
    assert_eq!(packet_header_len(crate::uapi::TPACKET_V1), Ok(32));
    assert_eq!(packet_header_len(crate::uapi::TPACKET_V2), Ok(32));
    assert_eq!(packet_header_len(crate::uapi::TPACKET_V3), Ok(48));
    assert_eq!(packet_header_len(3), Err(crate::NetError::Einval));
}
