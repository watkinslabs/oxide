#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

use super::uapi::*;

pub(super) fn raw_setsockopt(sock: &Arc<net::sock::InetSocket>, level: u64,
                            optname: u64, optval: u64, optlen: u32) -> Option<i64> {
    let kind = sock.kind.lock();
    // `ipv6_setsockopt` delegates SOL_IP only for non-raw sockets.  In
    // particular, an AF_INET6 raw socket must not acquire IPv4 option state
    // or an IPv4 Router Alert chain slot.
    if level == IPPROTO_IP && matches!(&*kind, net::sock::SockKind::Raw6(_)) {
        return Some(errno(Errno::Enoprotoopt));
    }
    // An ICMP datagram endpoint is not a raw socket: the caller-supplied-header
    // and message-filter options are not registered for it at any level.
    let ping = match &*kind {
        net::sock::SockKind::Raw4(endpoint) => endpoint.is_ping(),
        net::sock::SockKind::Raw6(endpoint) => endpoint.is_ping(),
        _ => false,
    };
    if ping {
        return match (level, optname) {
            (IPPROTO_IP, IP_HDRINCL) | (IPPROTO_RAW, ICMP_FILTER)
            | (IPPROTO_IPV6, IPV6_HDRINCL) | (IPPROTO_IPV6 | IPPROTO_RAW, IPV6_CHECKSUM)
            | (SOL_ICMPV6, ICMP6_FILTER) => Some(errno(Errno::Enoprotoopt)),
            _ => None,
        };
    }
    match (&*kind, level, optname) {
        (net::sock::SockKind::Raw4(endpoint), IPPROTO_IP, IP_HDRINCL) => {
            let value = match copy_u8_or_i32(optval, optlen) {
                Ok(value) => value, Err(error) => return Some(errno(error)),
            };
            endpoint.set_hdrincl(value != 0);
            Some(0)
        }
        (net::sock::SockKind::Raw4(endpoint), IPPROTO_RAW, ICMP_FILTER) => {
            if endpoint.protocol() != IPPROTO_ICMP { return Some(errno(Errno::Eopnotsupp)); }
            let mut bytes = endpoint.icmp_filter().to_ne_bytes();
            let count = core::cmp::min(optlen as usize, bytes.len());
            if uaccess::copy_from_user(&mut bytes[..count], optval).is_err() {
                return Some(errno(Errno::Efault));
            }
            endpoint.set_icmp_filter(u32::from_ne_bytes(bytes));
            Some(0)
        }
        (net::sock::SockKind::Raw6(endpoint), IPPROTO_IPV6, IPV6_HDRINCL) => {
            let value = match copy_i32(optval, optlen) { Ok(value) => value, Err(error) => return Some(errno(error)) };
            endpoint.set_header_included(value != 0);
            Some(0)
        }
        (net::sock::SockKind::Raw6(endpoint), level @ (IPPROTO_IPV6 | IPPROTO_RAW), IPV6_CHECKSUM) => {
            let value = match copy_i32(optval, optlen) { Ok(value) => value, Err(error) => return Some(errno(error)) };
            if endpoint.protocol() == IPPROTO_ICMPV6 && level == IPPROTO_IPV6 {
                return Some(errno(Errno::Einval));
            }
            Some(match endpoint.set_checksum(value) { Ok(()) => 0, Err(error) => crate::net_errno::errno_from_neterr(error) })
        }
        (net::sock::SockKind::Raw6(endpoint), SOL_ICMPV6, ICMP6_FILTER) => {
            if endpoint.protocol() != IPPROTO_ICMPV6 { return Some(errno(Errno::Eopnotsupp)); }
            let mut bytes = words_to_bytes(endpoint.icmp_filter().words());
            let count = core::cmp::min(optlen as usize, bytes.len());
            if uaccess::copy_from_user(&mut bytes[..count], optval).is_err() {
                return Some(errno(Errno::Efault));
            }
            endpoint.set_icmp_filter(net::raw6::Icmp6Filter::from_words(bytes_to_words(bytes)));
            Some(0)
        }
        _ => None,
    }
}

fn copy_i32(optval: u64, optlen: u32) -> Result<i32, Errno> {
    if optlen < core::mem::size_of::<i32>() as u32 { return Err(Errno::Einval); }
    let mut bytes = [0u8; core::mem::size_of::<i32>()];
    uaccess::copy_from_user(&mut bytes, optval).map_err(|_| Errno::Efault)?;
    Ok(i32::from_ne_bytes(bytes))
}

fn copy_u8_or_i32(optval: u64, optlen: u32) -> Result<i32, Errno> {
    if optlen == 0 { return Ok(0); }
    if optlen < core::mem::size_of::<i32>() as u32 {
        let mut value = [0u8; 1];
        uaccess::copy_from_user(&mut value, optval).map_err(|_| Errno::Efault)?;
        return Ok(i32::from(value[0]));
    }
    copy_i32(optval, optlen)
}

fn words_to_bytes(words: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    bytes
}

fn bytes_to_words(bytes: [u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (index, word) in words.iter_mut().enumerate() {
        let start = index * 4;
        *word = u32::from_ne_bytes([bytes[start], bytes[start + 1], bytes[start + 2], bytes[start + 3]]);
    }
    words
}

fn errno(error: Errno) -> i64 { -(error.as_i32() as i64) }
