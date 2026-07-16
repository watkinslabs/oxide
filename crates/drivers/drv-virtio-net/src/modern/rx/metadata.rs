const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;
const VIRTIO_NET_HDR_GSO_MASK: u8 = 0x7f;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// Decode receive offload state from a native `virtio_net_hdr`. # C: O(1)
pub(super) fn from_header(flags: u8, gso_type: u8) -> net::PacketRxMetadata {
    net::PacketRxMetadata {
        checksum: if flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            net::PacketChecksum::Partial
        } else if flags & VIRTIO_NET_HDR_F_DATA_VALID != 0 {
            net::PacketChecksum::Valid
        } else { net::PacketChecksum::None },
        gso_tcp: matches!(gso_type & VIRTIO_NET_HDR_GSO_MASK,
            VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6),
        vlan: None,
        queue: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_and_tcp_gso_flags_decode_independently() {
        assert_eq!(from_header(VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_TCPV4),
            net::PacketRxMetadata {
                checksum: net::PacketChecksum::Partial, gso_tcp: true, vlan: None, queue: 0,
            });
        assert_eq!(from_header(VIRTIO_NET_HDR_F_DATA_VALID, 0), net::PacketRxMetadata {
            checksum: net::PacketChecksum::Valid, gso_tcp: false, vlan: None, queue: 0,
        });
    }
}
