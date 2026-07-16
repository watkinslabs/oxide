use net::uapi::{VIRTIO_NET_HDR_F_DATA_VALID, VIRTIO_NET_HDR_F_NEEDS_CSUM};
#[cfg(test)]
use net::uapi::VIRTIO_NET_HDR_GSO_TCPV4;

/// Decode receive offload state from a native `virtio_net_hdr`. # C: O(1)
pub(super) fn from_header(header: &[u8; 12]) -> net::PacketRxMetadata {
    let flags = header[0];
    net::PacketRxMetadata {
        checksum: if flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            net::PacketChecksum::Partial
        } else if flags & VIRTIO_NET_HDR_F_DATA_VALID != 0 {
            net::PacketChecksum::Valid
        } else { net::PacketChecksum::None },
        virtio: net::PacketVirtioMetadata {
            gso_type: header[1],
            header_len: u16::from_le_bytes([header[2], header[3]]),
            gso_size: u16::from_le_bytes([header[4], header[5]]),
            checksum_start: u16::from_le_bytes([header[6], header[7]]),
            checksum_offset: u16::from_le_bytes([header[8], header[9]]),
        },
        vlan: None, queue: 0,
        ..net::PacketRxMetadata::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_and_tcp_gso_flags_decode_independently() {
        let mut header = [0u8; 12];
        header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM; header[1] = VIRTIO_NET_HDR_GSO_TCPV4;
        header[2..4].copy_from_slice(&54u16.to_le_bytes());
        header[4..6].copy_from_slice(&1200u16.to_le_bytes());
        header[6..8].copy_from_slice(&34u16.to_le_bytes());
        header[8..10].copy_from_slice(&16u16.to_le_bytes());
        assert_eq!(from_header(&header),
            net::PacketRxMetadata {
                checksum: net::PacketChecksum::Partial,
                virtio: net::PacketVirtioMetadata { gso_type: 1, header_len: 54,
                    gso_size: 1200, checksum_start: 34, checksum_offset: 16 },
                vlan: None, queue: 0,
                ..net::PacketRxMetadata::default()
            });
        header = [0; 12]; header[0] = VIRTIO_NET_HDR_F_DATA_VALID;
        assert_eq!(from_header(&header), net::PacketRxMetadata {
            checksum: net::PacketChecksum::Valid,
            virtio: net::PacketVirtioMetadata::default(), vlan: None, queue: 0,
            ..net::PacketRxMetadata::default()
        });
    }
}
