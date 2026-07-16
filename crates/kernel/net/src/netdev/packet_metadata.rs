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
pub struct PacketRxMetadata {
    pub checksum: PacketChecksum,
    pub gso_tcp: bool,
    pub vlan: Option<PacketVlan>,
}
