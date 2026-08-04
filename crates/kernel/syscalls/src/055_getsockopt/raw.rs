#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;
use net::sock::SockKind;

use super::out::OptOut;
use super::uapi::*;

/// Raw-socket-owned readbacks, which answer for a `SockKind::Raw*` endpoint
/// and report ENOPROTOOPT for every other shape. `None` = not a raw option.
/// # C: O(1)
pub(super) fn get(sock: &Arc<net::sock::InetSocket>, level: u64, optname: u64,
                  out: &OptOut) -> Option<i64> {
    // Linux's IPv6 option dispatcher does not delegate SOL_IP for SOCK_RAW.
    // Answer before the individual IPv4 tables can expose state a raw IPv6
    // socket was never permitted to set.
    if level == IPPROTO_IP && matches!(&*sock.kind.lock(), SockKind::Raw6(_)) {
        return Some(-(Errno::Enoprotoopt.as_i32() as i64));
    }
    Some(match (level, optname) {
        (IPPROTO_IP, IP_HDRINCL) => match &*sock.kind.lock() {
            SockKind::Raw4(endpoint) if !endpoint.is_ping() =>
                out.i32(i32::from(endpoint.hdrincl())),
            _ => -(Errno::Enoprotoopt.as_i32() as i64),
        },
        (IPPROTO_RAW, ICMP_FILTER) => match &*sock.kind.lock() {
            SockKind::Raw4(endpoint) if endpoint.is_ping() =>
                -(Errno::Enoprotoopt.as_i32() as i64),
            SockKind::Raw4(endpoint) if endpoint.protocol() == IPPROTO_ICMP =>
                out.bytes(&endpoint.icmp_filter().to_ne_bytes()),
            SockKind::Raw4(_) => -(Errno::Eopnotsupp.as_i32() as i64),
            _ => -(Errno::Enoprotoopt.as_i32() as i64),
        },
        (IPPROTO_IPV6, IPV6_HDRINCL) => match &*sock.kind.lock() {
            SockKind::Raw6(endpoint) if !endpoint.is_ping() =>
                out.i32(i32::from(endpoint.header_included())),
            _ => -(Errno::Enoprotoopt.as_i32() as i64),
        },
        (IPPROTO_IPV6, IPV6_CHECKSUM) | (IPPROTO_RAW, IPV6_CHECKSUM) => match &*sock.kind.lock() {
            SockKind::Raw6(endpoint) if !endpoint.is_ping() =>
                out.i32(endpoint.checksum().linux_value()),
            _ => -(Errno::Enoprotoopt.as_i32() as i64),
        },
        (SOL_ICMPV6, ICMP6_FILTER) => match &*sock.kind.lock() {
            SockKind::Raw6(endpoint) if endpoint.is_ping() =>
                -(Errno::Enoprotoopt.as_i32() as i64),
            SockKind::Raw6(endpoint) if endpoint.protocol() == IPPROTO_ICMPV6 => {
                let words = endpoint.icmp_filter().words();
                // SAFETY: eight initialized u32 words occupy exactly 32 readable
                // bytes; `words` outlives the borrow taken by `OptOut::bytes`.
                let bytes = unsafe {
                    core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), ICMP6_FILTER_BYTES)
                };
                out.bytes(bytes)
            }
            SockKind::Raw6(_) => -(Errno::Eopnotsupp.as_i32() as i64),
            _ => -(Errno::Enoprotoopt.as_i32() as i64),
        },
        _ => return None,
    })
}
