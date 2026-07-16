#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PacketChecksum {
    #[default]
    None,
    Partial,
    Valid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketVlan {
    pub tci: u16,
    pub tpid: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketVirtioMetadata {
    pub gso_type: u8,
    pub header_len: u16,
    pub gso_size: u16,
    pub checksum_start: u16,
    pub checksum_offset: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketRxMetadata {
    pub checksum: PacketChecksum,
    pub virtio: PacketVirtioMetadata,
    pub vlan: Option<PacketVlan>,
    /// Linux skb receive-queue mapping consumed by PACKET_FANOUT_QM.
    pub queue: u16,
    /// Driver-provided realtime software receive timestamp.
    pub software_timestamp_ns: Option<u64>,
    /// Driver-provided raw hardware receive timestamp.
    pub raw_hardware_timestamp_ns: Option<u64>,
}
