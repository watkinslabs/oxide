use crate::{PacketChecksum, PacketRxMetadata, PacketVlan};

pub(crate) use crate::uapi::{TP_STATUS_COPY, TP_STATUS_TS_RAW_HARDWARE,
                            TP_STATUS_TS_SOFTWARE};
use crate::uapi::{VIRTIO_NET_HDR_GSO_ECN, VIRTIO_NET_HDR_GSO_MASK,
    VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6,
    VIRTIO_NET_HDR_GSO_UDP_L4};
pub(crate) const VNET_HDR_SIZE: usize = super::packet_virtio::VNET_HEADER_LEN as usize;
pub(crate) const VNET_HDR_MAX_SIZE: usize = super::packet_virtio::VNET_MRG_HEADER_LEN as usize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketAuxData {
    pub status: u32,
    pub len: u32,
    pub snaplen: u32,
    pub mac: u16,
    pub net: u16,
    pub vlan_tci: u16,
    pub vlan_tpid: u16,
    pub(crate) vnet_hdr_size: u8,
    pub(crate) copy_thresh: bool,
    pub(crate) timestamp_ns: Option<u64>,
    pub(crate) timestamp_status: u32,
    pub(crate) vnet_header: [u8; VNET_HDR_MAX_SIZE],
}

impl PacketAuxData {
    /// Build receive metadata from packet and driver observations. # C: O(1)
    pub(crate) fn from_receive(original_len: usize, captured_len: usize, net: usize,
        pkttype: u8, metadata: PacketRxMetadata, inline_vlan: Option<PacketVlan>,
        datagram: bool) -> Self
    {
        let mut status = crate::uapi::TP_STATUS_USER;
        match metadata.checksum {
            PacketChecksum::Partial => status |= crate::uapi::TP_STATUS_CSUMNOTREADY,
            PacketChecksum::Valid if pkttype != crate::uapi::PACKET_OUTGOING =>
                status |= crate::uapi::TP_STATUS_CSUM_VALID,
            PacketChecksum::None | PacketChecksum::Valid => {}
        }
        if matches!(metadata.virtio.gso_type & VIRTIO_NET_HDR_GSO_MASK,
            VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6)
        { status |= crate::uapi::TP_STATUS_GSO_TCP; }
        let vlan = metadata.vlan.or(if datagram { inline_vlan } else { None });
        if vlan.is_some() {
            status |= crate::uapi::TP_STATUS_VLAN_VALID
                | crate::uapi::TP_STATUS_VLAN_TPID_VALID;
        }
        Self {
            status,
            len: original_len.min(u32::MAX as usize) as u32,
            snaplen: captured_len.min(u32::MAX as usize) as u32,
            mac: 0,
            net: net.min(u16::MAX as usize) as u16,
            vlan_tci: vlan.map_or(0, |tag| tag.tci),
            vlan_tpid: vlan.map_or(0, |tag| tag.tpid),
            vnet_hdr_size: 0,
            copy_thresh: false,
            timestamp_ns: None,
            timestamp_status: 0,
            vnet_header: [0; VNET_HDR_MAX_SIZE],
        }
    }

    /// Encode native Linux `struct tpacket_auxdata`. # C: O(1)
    pub fn to_ne_bytes(self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&self.status.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.len.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.snaplen.to_ne_bytes());
        bytes[12..14].copy_from_slice(&self.mac.to_ne_bytes());
        bytes[14..16].copy_from_slice(&self.net.to_ne_bytes());
        bytes[16..18].copy_from_slice(&self.vlan_tci.to_ne_bytes());
        bytes[18..20].copy_from_slice(&self.vlan_tpid.to_ne_bytes());
        bytes
    }
}

/// Select Linux packet-ring timestamp source and status. # C: O(1)
pub(crate) fn receive_timestamp(metadata: PacketRxMetadata, requested: i32,
                                realtime_ns: u64) -> (u64, u32) {
    if requested & crate::uapi::SOF_TIMESTAMPING_RAW_HARDWARE != 0 {
        if let Some(ns) = metadata.raw_hardware_timestamp_ns {
            return (ns, TP_STATUS_TS_RAW_HARDWARE);
        }
    }
    if requested & crate::uapi::SOF_TIMESTAMPING_SOFTWARE != 0 {
        if let Some(ns) = metadata.software_timestamp_ns {
            return (ns, TP_STATUS_TS_SOFTWARE);
        }
    }
    metadata.software_timestamp_ns.map_or((realtime_ns, 0),
        |ns| (ns, TP_STATUS_TS_SOFTWARE))
}

/// Encode Linux's 10/12-byte receive `virtio_net_hdr`. # C: O(1)
pub(crate) fn receive_vnet_header(metadata: PacketRxMetadata)
    -> crate::NetResult<[u8; VNET_HDR_MAX_SIZE]>
{
    let flags = match metadata.checksum {
        PacketChecksum::Partial => 1,
        PacketChecksum::Valid => 2,
        PacketChecksum::None => 0,
    };
    let gso = metadata.virtio.gso_type;
    if !matches!(gso & VIRTIO_NET_HDR_GSO_MASK, 0 | VIRTIO_NET_HDR_GSO_TCPV4
        | VIRTIO_NET_HDR_GSO_TCPV6 | VIRTIO_NET_HDR_GSO_UDP_L4)
        || gso == VIRTIO_NET_HDR_GSO_ECN {
        return Err(crate::NetError::Einval);
    }
    let encoded = super::packet_virtio::VirtioHeader {
        flags, gso_type: metadata.virtio.gso_type,
        hdr_len: metadata.virtio.header_len, gso_size: metadata.virtio.gso_size,
        csum_start: metadata.virtio.checksum_start,
        csum_offset: metadata.virtio.checksum_offset,
    }.encode(super::packet_virtio::VNET_MRG_HEADER_LEN);
    let mut header = [0u8; VNET_HDR_MAX_SIZE];
    header.copy_from_slice(&encoded);
    Ok(header)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketReceive {
    pub addr: super::PacketAddr,
    pub aux: PacketAuxData,
}

/// Require room for one complete configured receive VNET header. # C: O(1)
pub(crate) fn validate_vnet_receive_capacity(header_size: u8, max_len: usize)
    -> crate::NetResult<()>
{
    if max_len < header_size as usize { Err(crate::NetError::Einval) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auxdata_native_layout_and_valid_checksum_status_are_exact() {
        let aux = PacketAuxData::from_receive(1500, 64, 18,
            crate::uapi::PACKET_HOST, PacketRxMetadata {
                checksum: PacketChecksum::Valid,
                virtio: crate::PacketVirtioMetadata::default(),
                vlan: Some(PacketVlan { tci: 0x321, tpid: crate::eth_p::VLAN_AD }),
                queue: 0,
                ..PacketRxMetadata::default()
            }, None, false);
        assert_eq!(aux.status, crate::uapi::TP_STATUS_USER
            | crate::uapi::TP_STATUS_CSUM_VALID | crate::uapi::TP_STATUS_VLAN_VALID
            | crate::uapi::TP_STATUS_VLAN_TPID_VALID);
        let bytes = aux.to_ne_bytes();
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), aux.status);
        assert_eq!(u32::from_ne_bytes(bytes[4..8].try_into().unwrap()), 1500);
        assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 64);
        assert_eq!(u16::from_ne_bytes(bytes[14..16].try_into().unwrap()), 18);
        assert_eq!(u16::from_ne_bytes(bytes[16..18].try_into().unwrap()), 0x321);
        assert_eq!(u16::from_ne_bytes(bytes[18..20].try_into().unwrap()), crate::eth_p::VLAN_AD);

        let outgoing = PacketAuxData::from_receive(10, 10, 0,
            crate::uapi::PACKET_OUTGOING, PacketRxMetadata {
                checksum: PacketChecksum::Valid, ..PacketRxMetadata::default()
            }, None, false);
        assert_eq!(outgoing.status, crate::uapi::TP_STATUS_USER,
            "Linux does not report CSUM_VALID on outgoing observations");
    }
}
