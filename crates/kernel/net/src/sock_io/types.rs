use crate::addr::NetIfaceId;
use crate::sock::PacketReceive;
use crate::Ipv4Addr;

/// Kernel-owned result for one socket receive operation. Every field beyond
/// the payload backs one receive ancillary message (`crate::cmsg`), so a
/// receive path that captures nothing simply leaves them at their defaults.
#[derive(Default)]
pub struct Received {
    pub payload: alloc::vec::Vec<u8>,
    pub full_len: usize,
    pub peer: Option<(Ipv4Addr, u16)>,
    pub peer6: Option<(crate::Ipv6Addr, u16, u32)>,
    pub pktinfo: Option<(Ipv4Addr, NetIfaceId)>,
    pub pktinfo6: Option<(crate::Ipv6Addr, NetIfaceId)>,
    pub hoplimit: Option<u8>,
    /// Received IPv6 traffic class, delivered as an IPV6_TCLASS ancillary
    /// cmsg when the socket enabled IPV6_RECVTCLASS. Twin of `hoplimit`.
    pub tclass: Option<u8>,
    pub ttl: Option<u8>,
    /// Received IPv4 type-of-service byte, published by IP_RECVTOS.
    pub tos: Option<u8>,
    /// Received IPv4 header option area, published by IP_RECVOPTS, and echoed
    /// by IP_RETOPTS.
    pub options: alloc::vec::Vec<u8>,
    /// Datagram destination port, which completes the socket address
    /// IP_RECVORIGDSTADDR and IPV6_RECVORIGDSTADDR publish.
    pub dport: u16,
    /// Largest fragment the datagram was reassembled from, published by
    /// IP_RECVFRAGSIZE and IPV6_RECVFRAGSIZE.
    pub frag_max: u32,
    /// Received IPv6 flow-info field, published by IPV6_FLOWINFO.
    pub flowinfo: u32,
    /// Received IPv6 extension headers in wire order, published by
    /// IPV6_HOPOPTS, IPV6_DSTOPTS, IPV6_RTHDR and their compatibility twins.
    pub ext_headers: alloc::vec::Vec<(u8, alloc::vec::Vec<u8>)>,
    pub packet: Option<PacketReceive>,
    /// `UDP_GRO`: the segment size a coalesced receive was assembled from, so
    /// the reader can split the payload back into datagrams. `None` when this
    /// receive is one datagram, which is when no such control message exists.
    pub gro: Option<i32>,
}

impl Received {
    /// A 0-byte receive — Linux's end-of-stream answer, `*err = 0` with no
    /// payload. `payload` is a parameter because TCP reports EOF only after
    /// handing back whatever it had already copied. # C: O(1)
    pub fn eof(payload: alloc::vec::Vec<u8>) -> Self {
        Self { payload, ..Default::default() }
    }
}

/// THE empty-receive decision, for every socket family — Linux
/// `__skb_wait_for_more_packets` (`net/core/datagram.c`):
///
///     /* Socket shut down? */
///     if (sk->sk_shutdown & RCV_SHUTDOWN)
///             goto out_noerr;      /* -> *err = 0, i.e. EOF */
///
/// Linux makes this call ONCE, below every protocol, which is why no protocol
/// can get it wrong. `recv_from_socket` used to re-derive it per arm: six arms
/// carried an identical copy of the shutdown test and three AF_UNIX arms did
/// not, so a shut-down AF_UNIX reader was told EAGAIN while `poll` reported
/// POLLIN — an unkillable `epoll_wait`/`recvmsg` spin that shipped three times
/// (STREAM, then SEQPACKET and DGRAM). Route every arm through here; do not
/// reintroduce a bare `Err(Eagain)` for an empty queue.
/// # C: O(1)
pub fn recv_empty(read_shutdown: bool) -> Result<Received, crate::NetError> {
    recv_empty_with(read_shutdown, alloc::vec::Vec::new())
}

/// [`recv_empty`] for a caller that already copied bytes out (TCP). # C: O(1)
pub fn recv_empty_with(read_shutdown: bool, payload: alloc::vec::Vec<u8>)
    -> Result<Received, crate::NetError>
{
    if read_shutdown { Ok(Received::eof(payload)) } else { Err(crate::NetError::Eagain) }
}

#[derive(Clone, Copy, Default)]
pub struct RecvOptions {
    pub peek: bool,
}
