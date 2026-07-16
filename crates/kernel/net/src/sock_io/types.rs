use crate::addr::NetIfaceId;
use crate::sock::PacketAddr;
use crate::Ipv4Addr;

/// Kernel-owned result for one socket receive operation.
pub struct Received {
    pub payload: alloc::vec::Vec<u8>,
    pub full_len: usize,
    pub peer: Option<(Ipv4Addr, u16)>,
    pub peer6: Option<(crate::Ipv6Addr, u16, u32)>,
    pub pktinfo: Option<(Ipv4Addr, NetIfaceId)>,
    pub pktinfo6: Option<(crate::Ipv6Addr, NetIfaceId)>,
    pub hoplimit: Option<u8>,
    pub ttl: Option<u8>,
    pub packet: Option<PacketAddr>,
}

#[derive(Clone, Copy, Default)]
pub struct RecvOptions {
    pub peek: bool,
}
