// The lengths and bytes each `*_getname` hands back through the value-result
// `addrlen`. Callers size their own parsing off these, so an off-by-one is a
// silent mis-parse rather than an error.

use super::*;

#[test]
fn unbound_af_unix_name_is_family_only() {
    // `unix_getname`: `err = offsetof(struct sockaddr_un, sun_path)` == 2.
    let sa = encoded_sockaddr_un(None);
    assert_eq!(sa.len(), 2);
    assert_eq!(sa.as_bytes(), &[AF_UNIX.to_ne_bytes()[0], AF_UNIX.to_ne_bytes()[1]]);
    // An empty (rather than absent) name is the same socket state.
    assert_eq!(encoded_sockaddr_un(Some(&[])).len(), 2);
}

#[test]
fn pathname_af_unix_name_counts_the_trailing_nul() {
    // `unix_mkname_bsd`: `addr->len = strlen(sun_path) + 1 + offsetof(...)`.
    let sa = encoded_sockaddr_un(Some(b"/run/x"));
    assert_eq!(sa.len(), 2 + 6 + 1);
    assert_eq!(&sa.as_bytes()[2..8], b"/run/x");
    assert_eq!(sa.as_bytes()[8], 0, "pathname names are NUL-terminated");
}

#[test]
fn abstract_af_unix_name_keeps_its_leading_nul_and_adds_none() {
    // An abstract name is `\0` + `namelen` raw bytes: `unix_validate_addr`
    // keeps the caller's length verbatim, so there is NO terminator and the
    // name may contain interior NULs.
    let sa = encoded_sockaddr_un(Some(b"\0foo"));
    assert_eq!(sa.len(), 2 + 4, "no trailing NUL is appended to an abstract name");
    assert_eq!(&sa.as_bytes()[2..6], b"\0foo");
    let interior = encoded_sockaddr_un(Some(b"\0a\0b"));
    assert_eq!(interior.len(), 2 + 4);
    assert_eq!(&interior.as_bytes()[2..6], b"\0a\0b");
}

#[test]
fn af_unix_name_is_clamped_to_unix_path_max() {
    let long = [b'x'; 200];
    let sa = encoded_sockaddr_un(Some(&long));
    assert_eq!(sa.len(), SOCKADDR_UN_LEN, "never exceeds sizeof(struct sockaddr_un)");
}

#[test]
fn inet_and_inet6_lengths_match_their_structs() {
    let v4 = encoded_sockaddr_in(0x0100_007f, 80u16.to_be());
    assert_eq!(v4.len(), 16);
    assert_eq!(&v4.as_bytes()[8..16], &[0u8; 8], "sin_zero is cleared");
    let v6 = encoded_sockaddr_in6([0u8; 16], 80u16.to_be(), 3, 0);
    assert_eq!(v6.len(), 28);
    assert_eq!(&v6.as_bytes()[4..8], &[0u8; 4], "sin6_flowinfo is zero without IPV6_FLOWINFO_SEND");
    assert_eq!(&v6.as_bytes()[24..28], &3u32.to_ne_bytes(), "sin6_scope_id trails the address");
    // The word is network order, between the port and the address.
    let flowed = encoded_sockaddr_in6([0u8; 16], 80u16.to_be(), 3, 0x0012_3456);
    assert_eq!(&flowed.as_bytes()[4..8], &0x0012_3456u32.to_be_bytes());
}

#[test]
fn v4_mapped_bytes_match_ipv6_addr_set_v4mapped() {
    assert_eq!(v4_mapped_bytes(net::Ipv4Addr::ANY),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
        "the unspecified v4 address remains a v4-mapped IPv6 address");
    // 127.0.0.1 is `::ffff:127.0.0.1` — NOT `::1`. Collapsing it to the IPv6
    // loopback reports an address the peer never used and that no
    // v4-mapped comparison in userspace will match.
    assert_eq!(v4_mapped_bytes(net::Ipv4Addr::LOOPBACK),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
    assert_eq!(v4_mapped_bytes(net::Ipv4Addr::new(10, 1, 2, 3)),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3]);
}

#[test]
fn netlink_name_is_always_twelve_bytes_with_zero_pad() {
    let sa = encoded_sockaddr_nl(1234, 0x8);
    assert_eq!(sa.len(), 12);
    assert_eq!(&sa.as_bytes()[2..4], &[0, 0], "nl_pad is reserved and zero");
    assert_eq!(&sa.as_bytes()[4..8], &1234u32.to_ne_bytes());
    assert_eq!(&sa.as_bytes()[8..12], &0x8u32.to_ne_bytes());
}

#[test]
fn packet_name_length_tracks_the_hardware_address_length() {
    let mut meta = net::sock::PacketAddr {
        ifindex: 2, protocol: 0x0800, hatype: 1, pkttype: 0, halen: 6,
        addr: [0x52, 0x54, 0, 1, 2, 3, 0, 0],
    };
    let sa = encoded_sockaddr_ll(meta);
    assert_eq!(sa.len(), 12 + 6, "offsetof(sockaddr_ll, sll_addr) + sll_halen");
    assert_eq!(&sa.as_bytes()[2..4], &0x0800u16.to_be_bytes(), "sll_protocol is network order");
    assert_eq!(sa.as_bytes()[10], 0, "packet_getname leaves sll_pkttype zero");
    assert_eq!(sa.as_bytes()[11], 6);
    assert_eq!(&sa.as_bytes()[12..18], &[0x52, 0x54, 0, 1, 2, 3]);
    // A vanished interface keeps ifindex/protocol but reports no link address,
    // matching `dev_get_by_index_rcu` returning NULL.
    meta.hatype = 0; meta.halen = 0;
    assert_eq!(encoded_sockaddr_ll(meta).len(), 12);
}

#[test]
fn vsock_name_is_always_sizeof_sockaddr_vm() {
    let sa = encoded_sockaddr_vm(1024, 3);
    assert_eq!(sa.len(), 16);
    assert_eq!(&sa.as_bytes()[4..8], &1024u32.to_ne_bytes());
    assert_eq!(&sa.as_bytes()[8..12], &3u32.to_ne_bytes());
}

#[test]
fn a_dual_stack_socket_on_the_v4_path_reports_the_mapped_address() {
    use net::{Ipv4Addr, Ipv6Addr};
    // Native v6: the IPv6 field wins even when a v4 address is also present.
    assert!(!v6_name_is_v4_mapped(Ipv6Addr::LOOPBACK, Ipv4Addr::LOOPBACK));
    // Dual-stack on the v4 path: `sk_v6_rcv_saddr` is `::`, the v4 tuple is
    // live -> Linux reports `::ffff:a.b.c.d`, not `[::]`.
    assert!(v6_name_is_v4_mapped(Ipv6Addr::ANY, Ipv4Addr::new(10, 0, 0, 5)));
    // A wildcard-bound v6 socket with no v4 address stays `[::]`.
    assert!(!v6_name_is_v4_mapped(Ipv6Addr::ANY, Ipv4Addr::ANY));
}
