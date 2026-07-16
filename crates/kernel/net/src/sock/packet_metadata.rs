use crate::{PacketChecksum, PacketRxMetadata, PacketVlan};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketAuxData {
    pub status: u32,
    pub len: u32,
    pub snaplen: u32,
    pub mac: u16,
    pub net: u16,
    pub vlan_tci: u16,
    pub vlan_tpid: u16,
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
        if metadata.gso_tcp { status |= crate::uapi::TP_STATUS_GSO_TCP; }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketReceive {
    pub addr: super::PacketAddr,
    pub aux: PacketAuxData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auxdata_native_layout_and_valid_checksum_status_are_exact() {
        let aux = PacketAuxData::from_receive(1500, 64, 18,
            crate::uapi::PACKET_HOST, PacketRxMetadata {
                checksum: PacketChecksum::Valid,
                gso_tcp: false,
                vlan: Some(PacketVlan { tci: 0x321, tpid: crate::eth_p::VLAN_AD }),
                queue: 0,
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
