// Pure kernel→user `struct sockaddr` encoders for `getsockname(2)` /
// `getpeername(2)` / `accept(2)` / `recvfrom(2)`. No user memory, no `hal`,
// no cfg gating — `net_sockaddr.rs` re-exports these into the kernel-only
// marshalling layer, and hosted `cargo test` drives them directly. Every
// length here is the value Linux's `*_getname` returns through the
// value-result `addrlen`, which callers compare against and use to size
// their own parsing.

use net::sock::InetSocket;

pub(crate) const AF_INET:  u32 = 2;
pub(crate) const AF_INET6: u32 = 10;
pub(crate) const AF_UNIX:  u16 = 1;
pub(crate) const AF_NETLINK: u16 = 16;
pub(crate) const AF_PACKET: u16 = 17;

pub(crate) const SOCKADDR_UN_LEN:    usize = 110;
pub(crate) const SOCKADDR_IN_LEN:    usize = 16;
pub(crate) const SOCKADDR_IN6_LEN:   usize = 28;
pub(crate) const SOCKADDR_NL_LEN:    usize = 12;
pub(crate) const SOCKADDR_LL_BASE_LEN: usize = 12;
/// `sockaddr_ll.sll_addr[8]`.
pub(crate) const SOCKADDR_LL_ADDR_LEN: usize = 8;
pub(crate) const SOCKADDR_VM_LEN:    usize = 16;
pub(crate) const SOCKADDR_STORAGE:   usize = SOCKADDR_UN_LEN;
/// `sizeof(sa_family_t)` — the length `unix_getname` returns for a socket
/// with no bound name at all.
pub(crate) const SA_FAMILY_LEN:      usize = 2;
/// `UNIX_PATH_MAX` (`sizeof(sockaddr_un.sun_path)`).
const UNIX_PATH_MAX: usize = SOCKADDR_UN_LEN - SA_FAMILY_LEN;

pub(crate) struct EncodedSockaddr {
    pub(crate) bytes: [u8; SOCKADDR_STORAGE],
    len:   usize,
}

impl EncodedSockaddr {
    pub(crate) fn new(len: usize) -> Self { Self { bytes: [0; SOCKADDR_STORAGE], len } }
    pub(crate) fn as_bytes(&self) -> &[u8] { &self.bytes[..self.len] }
    pub(crate) fn len(&self) -> usize { self.len }
    pub(crate) fn put_u16(&mut self, off: usize, v: u16) {
        self.bytes[off..off + 2].copy_from_slice(&v.to_ne_bytes());
    }
    pub(crate) fn put_u32(&mut self, off: usize, v: u32) {
        self.bytes[off..off + 4].copy_from_slice(&v.to_ne_bytes());
    }
}

/// AF_UNIX name encoding returns:
///   * `offsetof(struct sockaddr_un, sun_path)` == 2 for a socket with no
///     bound address — family only, no path byte at all;
///   * `addr->len` otherwise, which `unix_mkname_bsd` set to
///     `strlen(path) + 1 + 2` for a pathname (the trailing NUL IS counted)
///     and which `unix_validate_addr` kept verbatim for an abstract name —
///     a leading NUL followed by exactly `namelen` bytes with NO terminator,
///     because an abstract name may contain NULs and is not a C string.
/// # C: O(path len)
pub(crate) fn encoded_sockaddr_un(path: Option<&[u8]>) -> EncodedSockaddr {
    let bytes = path.unwrap_or(&[]);
    let path_len = bytes.len().min(UNIX_PATH_MAX);
    let needs_nul = path_len > 0 && bytes.first().copied() != Some(0);
    let len = SA_FAMILY_LEN + path_len + usize::from(needs_nul);
    let mut out = EncodedSockaddr::new(len.min(SOCKADDR_UN_LEN));
    out.put_u16(0, AF_UNIX);
    out.bytes[SA_FAMILY_LEN..SA_FAMILY_LEN + path_len].copy_from_slice(&bytes[..path_len]);
    out
}

/// `struct sockaddr_in` — `inet_getname` always returns `sizeof(*sin)` with
/// `sin_zero` cleared. # C: O(1)
pub(crate) fn encoded_sockaddr_in(addr_be: u32, port_be: u16) -> EncodedSockaddr {
    let mut out = EncodedSockaddr::new(SOCKADDR_IN_LEN);
    out.put_u16(0, AF_INET as u16);
    out.put_u16(2, port_be);
    out.put_u32(4, addr_be);
    out
}

/// `struct sockaddr_in6` — `inet6_getname` returns `sizeof(*sin)`.
/// `flowinfo` is the settled flow information a peer name reports, which is
/// zero for every local name and for a socket that never asked to send one
/// (`net::sock_opts::sol_ipv6::sndflow`). # C: O(1)
pub(crate) fn encoded_sockaddr_in6(addr_bytes: [u8; 16], port_be: u16, scope_id: u32,
    flowinfo: u32) -> EncodedSockaddr
{
    let mut out = EncodedSockaddr::new(SOCKADDR_IN6_LEN);
    out.put_u16(0, AF_INET6 as u16);
    out.put_u16(2, port_be);
    out.bytes[4..8].copy_from_slice(&flowinfo.to_be_bytes());
    out.bytes[8..24].copy_from_slice(&addr_bytes);
    out.put_u32(24, scope_id);
    out
}

/// Encode Linux `struct sockaddr_nl` — `netlink_getname` always returns 12
/// bytes and never ENOTCONN, even for `getpeername` on an unconnected socket.
/// # C: O(1)
pub(crate) fn encoded_sockaddr_nl(pid: u32, groups: u32) -> EncodedSockaddr {
    let mut out = EncodedSockaddr::new(SOCKADDR_NL_LEN);
    out.put_u16(0, AF_NETLINK);
    out.put_u16(2, 0);
    out.put_u32(4, pid);
    out.put_u32(8, groups);
    out
}

/// Encode Linux `struct sockaddr_ll` for AF_PACKET name queries —
/// `packet_getname` returns `offsetof(sockaddr_ll, sll_addr) + sll_halen`,
/// and falls back to `hatype = 0, halen = 0` when the bound interface has
/// disappeared. # C: O(1)
pub(crate) fn encoded_sockaddr_ll(meta: net::sock::PacketAddr) -> EncodedSockaddr {
    let address_len = core::cmp::min(meta.halen as usize, SOCKADDR_LL_ADDR_LEN);
    let mut out = EncodedSockaddr::new(SOCKADDR_LL_BASE_LEN + address_len);
    out.put_u16(0, AF_PACKET);
    out.bytes[2..4].copy_from_slice(&meta.protocol.to_be_bytes());
    out.put_u32(4, meta.ifindex);
    out.put_u16(8, meta.hatype);
    out.bytes[10] = meta.pkttype;
    out.bytes[11] = address_len as u8;
    out.bytes[SOCKADDR_LL_BASE_LEN..SOCKADDR_LL_BASE_LEN + address_len]
        .copy_from_slice(&meta.addr[..address_len]);
    out
}

/// Encode `struct sockaddr_vm` — `vsock_getname` returns
/// `sizeof(struct sockaddr_vm)`. # C: O(1)
pub(crate) fn encoded_sockaddr_vm(port: u32, cid: u64) -> EncodedSockaddr {
    let mut out = EncodedSockaddr::new(SOCKADDR_VM_LEN);
    out.put_u16(0, net::sock::AF_VSOCK as u16);
    out.put_u16(2, 0);
    out.put_u32(4, port);
    out.put_u32(8, cid as u32);
    out
}

/// `::ffff:a.b.c.d` for every IPv4 address, including `0.0.0.0` — Linux
/// `ipv6_addr_set_v4mapped`. # C: O(1)
pub(crate) fn v4_mapped_bytes(ip: net::Ipv4Addr) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[10] = 0xff; b[11] = 0xff;
    b[12..16].copy_from_slice(&ip.as_u32().to_be_bytes());
    b
}

/// Does an `AF_INET6` name query report the V4-MAPPED form of the socket's
/// IPv4 address rather than its IPv6 one? Linux `inet6_getname(peer = 0)`
/// reports `sk->sk_v6_rcv_saddr`, falling back to `np->saddr` when that is
/// unspecified. A dual-stack socket that connected to an IPv4 peer took the
/// IPv4 path, so it holds a live local address ONLY in the v4 tuple while its
/// `sk_v6_rcv_saddr` is still `::` — and Linux renders that as
/// `::ffff:a.b.c.d`. Reading the IPv6 field unconditionally reported `[::]`
/// for every such socket. # C: O(1)
pub(crate) fn v6_name_is_v4_mapped(ip6: net::Ipv6Addr, ip4: net::Ipv4Addr) -> bool {
    ip6.is_unspecified() && !ip4.is_unspecified()
}

/// Render a socket's IPv4 address tuple in the family the socket actually
/// speaks. A dual-stack `AF_INET6` socket whose peer/local tuple lives in the
/// IPv4 fields is exactly Linux's v4-mapped case: `tcp_v6_connect` stores
/// `::ffff:a.b.c.d` in `sk->sk_v6_daddr` before handing the connection to
/// `tcp_v4_connect`, and `inet6_getname` reports that verbatim. 127.0.0.1
/// maps to `::ffff:127.0.0.1`, NOT `::1` — those are different addresses.
/// # C: O(path len) for AF_UNIX, O(1) otherwise
pub(crate) fn encoded_sockaddr_for_socket(sock: &InetSocket, ip: net::Ipv4Addr, port: u16,
    flowinfo: u32) -> EncodedSockaddr
{
    let fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    if fam == net::sock::AF_UNIX {
        let path = net::sock::unix_local_path(sock);
        return encoded_sockaddr_un(path.as_deref());
    }
    if fam == net::sock::AF_INET6 {
        encoded_sockaddr_in6(v4_mapped_bytes(ip), port.to_be(), 0, flowinfo)
    } else {
        encoded_sockaddr_in(ip.as_u32().to_be(), port.to_be())
    }
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests;
