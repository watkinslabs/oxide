// `IPPROTO_IP` argument import + application for slot 54. The option table,
// capability ladder, value windows and errno ordering live in
// `net::sock_opts::sol_ip` (`docs/53§4`); this file only moves bytes and
// stores accepted results.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use net::sock::InetSocket;
use net::sock_opts::sol_ip::set::{self as ipset, Action, ArgClass};
use net::sock_opts::sol_ip::uapi::*;

use crate::net_common::errno_from_neterr;
use super::multicast::{
    SourceOp, ipv4_group_filter, ipv4_mcast_group_req, ipv4_mcast_group_source_req,
    ipv4_mcast_if, ipv4_mcast_membership, ipv4_mcast_source_req, ipv4_msfilter,
};
use super::optval::read_u8_or_i32_required;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `setsockopt(fd, IPPROTO_IP, ...)`. # C: O(optlen)
pub(super) fn set(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen: u32) -> i64 {
    match ipset::arg_class(optname) {
        ArgClass::Delegated => return delegated(sock, optname, optval, optlen),
        ArgClass::Policy => return match ipset::admit_policy(super::sol_socket::caps_for(sock)) {
            Err(e) => errno(e), Ok(_) => errno(Errno::Eopnotsupp),
        },
        ArgClass::Options => return set_options(sock, optval, optlen),
        ArgClass::ByteOrInt => {}
    }
    // The leading operand is imported for EVERY option at this level before
    // the number is classified: four bytes when the caller supplies them,
    // otherwise one, otherwise the value is zero.
    let val = match import(optval, optlen) { Ok(v) => v, Err(e) => return e };
    // The unicast interface option resolves a device before it is judged.
    if optname == IP_UNICAST_IF { return set_unicast_if(sock, val, optlen); }
    let caps = super::sol_socket::caps_for(sock);
    let action = match ipset::admit(optname, val, optlen, net::sock_opts::describe_ip(sock), caps) {
        Ok(a) => a, Err(e) => return errno(e),
    };
    apply(sock, action)
}

/// The byte-or-int import: a short but non-empty operand is one byte, an empty
/// one is zero, and only a faulting pointer is an error. # C: O(1)
fn import(optval: u64, optlen: u32) -> Result<i32, i64> {
    if optlen == 0 { return Ok(0); }
    read_u8_or_i32_required(optval, optlen)
}

fn apply(sock: &Arc<InetSocket>, action: Action) -> i64 {
    use net::sock_opts::sol_ip::state::flag;
    match action {
        Action::Flag { bit, on } => {
            sock.opts.ip.set_flag(bit, on);
            // Multicast delivery consults the shared membership object, which
            // the receive path already reaches, so there is nothing to mirror.
            if bit == flag::MC_ALL_OFF { sock.mcast.set_multicast_all_v4(!on); }
        }
        Action::PktInfo(on) => sock.opts.ip_pktinfo.store(i32::from(on), Ordering::Release),
        Action::RecvTtl(on) => sock.opts.ip_recvttl.store(i32::from(on), Ordering::Release),
        Action::RecvErr(on) => sock.error.set_recverr4(on),
        Action::Ttl(v) => sock.opts.ip_ttl.store(v, Ordering::Release),
        Action::Tos(v) => {
            let current = sock.opts.ip_tos.load(Ordering::Acquire);
            let stream = net::sock_opts::describe_ip(sock).stream;
            sock.opts.ip_tos.store(ipset::tos_value(v, current, stream), Ordering::Release);
        }
        Action::MinTtl(v) => sock.opts.min_hop.set_ttl(v),
        Action::MtuDiscover(v) => sock.opts.ip_mtu_discover.store(v, Ordering::Release),
        Action::UnicastIf(ifindex) => sock.opts.ip.set_unicast_if(ifindex),
        Action::LocalPortRange(packed) => sock.opts.ip.set_local_port_range(packed),
        Action::Options(compiled) => sock.opts.ip.set_options(compiled),
        Action::RouterAlert(on) => sock.opts.ip.set_flag(flag::RTALERT, on),
        Action::Delegated => return errno(Errno::Enoprotoopt),
    }
    0
}

/// `IP_OPTIONS`: import the caller's header option area, compile it, and
/// install it for every datagram the socket sends. # C: O(optlen)
fn set_options(sock: &Arc<InetSocket>, optval: u64, optlen: u32) -> i64 {
    if optlen as usize > MAX_IPOPTLEN { return errno(Errno::Einval); }
    let mut bytes = alloc::vec![0u8; optlen as usize];
    if optlen != 0 && uaccess::copy_from_user(&mut bytes, optval).is_err() {
        return errno(Errno::Efault);
    }
    match ipset::admit_options(&bytes, super::sol_socket::caps_for(sock)) {
        Ok(action) => apply(sock, action),
        Err(e) => errno(e),
    }
}

/// `IP_UNICAST_IF`: the operand names an interface in network order, which
/// must exist and must not contradict an existing device binding.
/// # C: O(ifaces)
fn set_unicast_if(sock: &Arc<InetSocket>, val: i32, optlen: u32) -> i64 {
    let requested = match ipset::unicast_if_request(val, optlen) {
        Ok(r) => r, Err(e) => return errno(e),
    };
    let Some(ifindex) = requested else {
        sock.opts.ip.set_unicast_if(0);
        return 0;
    };
    let master = net::sock::iface::l3_master_index(sock.net_ns(), ifindex);
    let bound = sock.opts.bound_ifindex.load(Ordering::Acquire) as i32;
    match ipset::unicast_if_admit(ifindex, master, bound) {
        Ok(action) => apply(sock, action),
        Err(e) => errno(e),
    }
}

/// The multicast, source-filter and raw-socket options keep their own owners.
/// # C: O(sources)
fn delegated(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen: u32) -> i64 {
    match optname {
        IP_ADD_MEMBERSHIP => ipv4_mcast_membership(sock, optval, optlen, true),
        IP_DROP_MEMBERSHIP => ipv4_mcast_membership(sock, optval, optlen, false),
        IP_MULTICAST_IF => {
            if optlen < 4 { return errno(Errno::Einval); }
            ipv4_mcast_if(sock, optval, optlen)
        }
        IP_MULTICAST_TTL => {
            if net::sock_opts::describe_ip(sock).stream { return errno(Errno::Einval); }
            if optlen == 0 { return errno(Errno::Einval); }
            let v = match read_u8_or_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            let v = if v == TTL_ROUTE_DEFAULT { DEFAULT_MULTICAST_TTL } else { v };
            if !(0..=TTL_MAX).contains(&v) { return errno(Errno::Einval); }
            encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V4Ttl(v)))
        }
        IP_MULTICAST_LOOP => {
            if optlen == 0 { return errno(Errno::Einval); }
            let v = match read_u8_or_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V4Loop(v)))
        }
        IP_ADD_SOURCE_MEMBERSHIP => ipv4_mcast_source_req(sock, optval, optlen, SourceOp::Join),
        IP_DROP_SOURCE_MEMBERSHIP => ipv4_mcast_source_req(sock, optval, optlen, SourceOp::Leave),
        IP_BLOCK_SOURCE => ipv4_mcast_source_req(sock, optval, optlen, SourceOp::Block),
        IP_UNBLOCK_SOURCE => ipv4_mcast_source_req(sock, optval, optlen, SourceOp::Unblock),
        IP_MSFILTER => ipv4_msfilter(sock, optval, optlen),
        MCAST_JOIN_GROUP => ipv4_mcast_group_req(sock, optval, optlen, true),
        MCAST_LEAVE_GROUP => ipv4_mcast_group_req(sock, optval, optlen, false),
        MCAST_JOIN_SOURCE_GROUP => ipv4_mcast_group_source_req(sock, optval, optlen, SourceOp::Join),
        MCAST_LEAVE_SOURCE_GROUP => ipv4_mcast_group_source_req(sock, optval, optlen, SourceOp::Leave),
        MCAST_BLOCK_SOURCE => ipv4_mcast_group_source_req(sock, optval, optlen, SourceOp::Block),
        MCAST_UNBLOCK_SOURCE => ipv4_mcast_group_source_req(sock, optval, optlen, SourceOp::Unblock),
        MCAST_MSFILTER => ipv4_group_filter(sock, optval, optlen),
        // `IP_HDRINCL` reaches its raw-socket owner before this table runs, so
        // arriving here means the socket is not a raw one.
        _ => errno(Errno::Enoprotoopt),
    }
}

fn encode(result: net::NetResult<()>) -> i64 {
    match result { Ok(()) => 0, Err(error) => errno_from_neterr(error) }
}
