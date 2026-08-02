// `IPPROTO_IPV6` argument import + application for slot 54. The option table,
// capability ladder, value windows and errno ordering live in
// `net::sock_opts::sol_ipv6` (`docs/53§4`); this file only moves bytes and
// stores accepted results.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use net::sock::InetSocket;
use net::sock_opts::sol_ipv6::set::{self as v6set, Action, ArgClass};
use net::sock_opts::sol_ipv6::state::Sticky;
use net::sock_opts::sol_ipv6::uapi::*;
use net::sock_opts::sol_ipv6::{flowlabel, hdr};

use crate::net_errno::errno_from_neterr;
use super::multicast::{
    SourceOp, ipv6_group_filter, ipv6_mcast_group_req, ipv6_mcast_group_source_req,
    ipv6_mcast_membership,
};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `setsockopt(fd, IPPROTO_IPV6, ...)`. # C: O(optlen)
pub(super) fn set(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen: u32) -> i64 {
    if let Err(e) = require_v6(sock) { return e; }
    let caps = super::sol_socket::caps_for(sock);
    match v6set::arg_class(optname) {
        ArgClass::Delegated => return delegated(sock, optname, optval, optlen),
        ArgClass::Policy => return match v6set::admit_policy(caps) {
            Err(e) => errno(e), Ok(_) => errno(Errno::Eopnotsupp),
        },
        ArgClass::Header => return set_header(sock, optname, optval, optlen, caps),
        ArgClass::PktInfo => return set_pktinfo(sock, optval, optlen),
        ArgClass::NextHop => return set_nexthop(sock, optval, optlen, caps),
        ArgClass::FlowLabel => return flow_label(sock, optval, optlen, caps),
        // The ancillary-message stream form of the sticky headers: an empty
        // write clears every slot, and anything else is an option list this
        // table does not parse in the option path.
        ArgClass::PktOptions => {
            if optlen == 0 {
                for slot in [Sticky::HopOpts, Sticky::RthdrDstOpts, Sticky::Rthdr,
                    Sticky::DstOpts]
                {
                    sock.opts.ipv6.set_header(slot, None);
                }
                return 0;
            }
            return errno(Errno::Einval);
        }
        ArgClass::Int => {}
    }
    // This level reads a whole `int` or nothing at all: a short operand is
    // simply zero, never a byte.
    let val = match import(optval, optlen) { Ok(v) => v, Err(e) => return errno(e) };
    let sock_view = net::sock_opts::describe_ipv6(sock);
    match optname {
        IPV6_MULTICAST_IF => return set_multicast_if(sock, val, optlen, sock_view),
        IPV6_UNICAST_IF => return set_unicast_if(sock, val, optlen),
        _ => {}
    }
    let action = match v6set::admit(optname, val, optlen, sock_view, caps) {
        Ok(a) => a, Err(e) => return errno(e),
    };
    apply(sock, action, val)
}

fn import(optval: u64, optlen: u32) -> Result<i32, Errno> {
    if optlen < 4 { return Ok(0); }
    let mut bytes = [0u8; 4];
    uaccess::copy_from_user(&mut bytes, optval).map_err(|_| Errno::Efault)?;
    Ok(i32::from_ne_bytes(bytes))
}

fn apply(sock: &Arc<InetSocket>, action: Action, raw_val: i32) -> i64 {
    use net::sock_opts::sol_ipv6::flag;
    match action {
        Action::Flag { bit, on } => {
            sock.opts.ipv6.set_flag(bit, on);
            match bit {
                v6set::RECVPKTINFO =>
                    sock.opts.ipv6_recvpktinfo.store(i32::from(on), Ordering::Release),
                v6set::RECVHOPLIMIT =>
                    sock.opts.ipv6_recvhoplimit.store(i32::from(on), Ordering::Release),
                v6set::RECVTCLASS =>
                    sock.opts.ipv6_recvtclass.store(i32::from(on), Ordering::Release),
                flag::MC_ALL_OFF => sock.mcast.set_multicast_all_v6(!on),
                flag::AUTOFLOWLABEL => sock.opts.ipv6.set_flag(flag::AUTOFLOWLABEL_SET, true),
                _ => {}
            }
        }
        // The shared nonlocal-bind pair: one storage word, written through the
        // `IPPROTO_IP` state whichever level's option number arrived.
        Action::InetFlag { bit, on } => sock.opts.ip.set_flag(bit, on),
        Action::RecvErr(on) => sock.error.set_recverr6(on),
        Action::UnicastHops(v) => sock.opts.ipv6_ucast_hops.store(v, Ordering::Release),
        Action::MulticastHops(v) =>
            return encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Hops(v))),
        Action::MulticastLoop(on) => return encode(
            sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Loop(i32::from(on)))),
        Action::MulticastIf(ifindex) => return encode(
            sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Iface(ifindex as i32))),
        Action::UnicastIf(ifindex) => sock.opts.ipv6.set_unicast_if(ifindex),
        Action::V6Only(on) => sock.opts.ipv6_v6only.store(i32::from(on), Ordering::Release),
        Action::MtuDiscover(v) => sock.opts.ipv6_mtu_discover.store(v, Ordering::Release),
        Action::FragSize(v) => sock.opts.ipv6.set_frag_size(v),
        Action::UseMinMtu(v) => sock.opts.ipv6.set_use_min_mtu(v),
        Action::MinHopCount(v) => sock.opts.min_hop.set_hopcount(v),
        Action::Tclass(v) => {
            let current = sock.opts.ipv6_tclass.load(Ordering::Acquire).max(0);
            let stream = net::sock_opts::describe_ipv6(sock).stream;
            sock.opts.ipv6_tclass.store(v6set::tclass_value(v, current, stream), Ordering::Release);
        }
        Action::SrcPrefs(_) => {
            let current = sock.opts.ipv6.srcprefs();
            match v6set::apply_src_prefs(current, raw_val) {
                Ok(next) => sock.opts.ipv6.set_srcprefs(next),
                Err(e) => return errno(e),
            }
        }
        // Converting to the IPv4 family retires every IPv6-only receive
        // personality along with the sticky headers, exactly as Linux does
        // before it swaps the protocol operations.
        Action::AddrForm => {
            sock.opts.ipv6.set_flag(u64::MAX, false);
            for slot in [Sticky::HopOpts, Sticky::RthdrDstOpts, Sticky::Rthdr, Sticky::DstOpts] {
                sock.opts.ipv6.set_header(slot, None);
            }
            sock.opts.ipv6_recvpktinfo.store(0, Ordering::Release);
            sock.opts.ipv6_recvhoplimit.store(0, Ordering::Release);
            sock.opts.ipv6_recvtclass.store(0, Ordering::Release);
            sock.family.store(net::sock::AF_INET, Ordering::Release);
        }
        Action::RouterAlert { selector, on } => {
            sock.opts.ipv6.set_ra_selector(
                selector.unwrap_or(net::router_alert::V6_NO_SLOT));
            sock.opts.ipv6.set_flag(flag::RTALERT, on)
        }
        Action::Delegated => return errno(Errno::Enoprotoopt),
    }
    0
}

/// `IPV6_HOPOPTS` / `IPV6_RTHDRDSTOPTS` / `IPV6_RTHDR` / `IPV6_DSTOPTS`.
/// # C: O(len)
fn set_header(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen: u32,
              caps: net::sock_opts::sol_socket::OptCaps) -> i64 {
    if optlen as usize > IPV6_OPT_MAX { return errno(Errno::Einval); }
    let mut bytes = alloc::vec![0u8; optlen as usize];
    if optlen != 0 && uaccess::copy_from_user(&mut bytes, optval).is_err() {
        return errno(Errno::Efault);
    }
    let slot = match hdr::slot(optname) { Some(s) => s, None => return errno(Errno::Enoprotoopt) };
    match hdr::admit(optname, &bytes, caps) {
        Ok(area) => { sock.opts.ipv6.set_header(slot, area); 0 }
        Err(e) => errno(e),
    }
}

/// `IPV6_PKTINFO`: the sticky source address and outgoing interface.
/// # C: O(1)
fn set_pktinfo(sock: &Arc<InetSocket>, optval: u64, optlen: u32) -> i64 {
    if (optlen as usize) < IN6_PKTINFO_SIZE {
        return errno(if optlen == 0 { Errno::Einval } else { Errno::Einval });
    }
    let mut bytes = [0u8; IN6_PKTINFO_SIZE];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() { return errno(Errno::Efault); }
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&bytes[..16]);
    let ifindex = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
    let bound = sock.opts.bound_ifindex.load(Ordering::Acquire) as i32;
    if let Err(e) = v6set::admit_pktinfo(optlen, ifindex, bound) { return errno(e); }
    sock.opts.ipv6.set_sticky_pktinfo(addr, ifindex);
    0
}

/// `IPV6_NEXTHOP`: the sticky first hop, named as an IPv6 socket address.
/// # C: O(1)
fn set_nexthop(sock: &Arc<InetSocket>, optval: u64, optlen: u32,
               caps: net::sock_opts::sol_socket::OptCaps) -> i64 {
    if optlen == 0 { sock.opts.ipv6.set_nexthop(None); return 0; }
    // A caller-chosen first hop bypasses the routing table, so it carries the
    // same privilege as a source route.
    if !caps.net_raw { return errno(Errno::Eperm); }
    // `struct sockaddr_in6`: family, port, flow info, then the address.
    const SOCKADDR_IN6_SIZE: usize = 28;
    if (optlen as usize) < SOCKADDR_IN6_SIZE { return errno(Errno::Einval); }
    let mut bytes = [0u8; SOCKADDR_IN6_SIZE];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() { return errno(Errno::Efault); }
    if u16::from_ne_bytes([bytes[0], bytes[1]]) != net::sock::AF_INET6 {
        return errno(Errno::Eafnosupport);
    }
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&bytes[8..24]);
    if addr == [0u8; 16] { sock.opts.ipv6.set_nexthop(None); return 0; }
    sock.opts.ipv6.set_nexthop(Some(addr));
    0
}

/// `IPV6_FLOWLABEL_MGR`: lease, renew or release one flow label. # C: O(labels)
fn flow_label(sock: &Arc<InetSocket>, optval: u64, optlen: u32,
              caps: net::sock_opts::sol_socket::OptCaps) -> i64 {
    if (optlen as usize) < IN6_FLOWLABEL_REQ_SIZE { return errno(Errno::Einval); }
    let mut bytes = [0u8; IN6_FLOWLABEL_REQ_SIZE];
    if uaccess::copy_from_user(&mut bytes, optval).is_err() { return errno(Errno::Efault); }
    let req = flowlabel::FlowReq::parse(&bytes);
    let ns = sock.net_ns();
    let table = flowlabel::table();
    match req.action {
        IPV6_FL_A_PUT => {
            if req.flags & IPV6_FL_F_REFLECT != 0 {
                if !net::sock_opts::describe_ipv6(sock).stream {
                    return errno(Errno::Enoprotoopt);
                }
                if !sock.opts.ipv6.flag(net::sock_opts::sol_ipv6::flag::REPFLOW) {
                    return errno(Errno::Esrch);
                }
                sock.opts.ipv6.set_flow_label(0);
                sock.opts.ipv6.set_flag(net::sock_opts::sol_ipv6::flag::REPFLOW, false);
                return 0;
            }
            if !sock.opts.ipv6.release_label(req.label) { return errno(Errno::Esrch); }
            if sock.opts.ipv6.flow_label() == req.label { sock.opts.ipv6.set_flow_label(0); }
            table.release(ns, req.label);
            0
        }
        IPV6_FL_A_RENEW => {
            let (linger, expires) = match flowlabel::admit_create(&req, caps) {
                Ok(v) => v, Err(e) => return errno(e),
            };
            let held = sock.opts.ipv6.holds_label(req.label);
            // A label the socket does not hold is renewable only by an
            // administrator, and only in the unshared mode.
            if !held && !(req.share == IPV6_FL_S_NONE && caps.net_admin) {
                return errno(Errno::Esrch);
            }
            match table.renew(ns, req.label, linger, expires, now_ns()) {
                Ok(()) => 0, Err(e) => errno(e),
            }
        }
        IPV6_FL_A_GET => {
            if req.flags & IPV6_FL_F_REFLECT != 0 {
                if !net::sock_opts::describe_ipv6(sock).stream {
                    return errno(Errno::Enoprotoopt);
                }
                sock.opts.ipv6.set_flag(net::sock_opts::sol_ipv6::flag::REPFLOW, true);
                return 0;
            }
            if req.label & !IPV6_FLOWINFO_FLOWLABEL != 0 { return errno(Errno::Einval); }
            let (linger, expires) = match flowlabel::admit_create(&req, caps) {
                Ok(v) => v, Err(e) => return errno(e),
            };
            let owner = owner_identity();
            if let Some(existing) = table.lookup(ns, req.label) {
                if req.flags & IPV6_FL_F_EXCL != 0 { return errno(Errno::Eexist); }
                if !flowlabel::shareable(&existing, req.share, owner) {
                    return errno(Errno::Eperm);
                }
            } else if req.flags & IPV6_FL_F_CREATE == 0 && req.label != 0 {
                return errno(Errno::Enoent);
            }
            let held = sock.opts.ipv6.take_labels();
            let count = held.len();
            for label in held { sock.opts.ipv6.hold_label(label); }
            if let Err(e) = table.admit_room(ns, count, caps) { return errno(e); }
            let now = now_ns();
            let lease = flowlabel::Lease {
                label: req.label, dst: req.dst, share: req.share, owner,
                linger_ns: linger, expires_ns: now + expires.max(linger), users: 1,
            };
            let interned = match table.intern(ns, lease, pick_label) {
                Ok(l) => l, Err(e) => return errno(e),
            };
            sock.opts.ipv6.hold_label(interned.label);
            sock.opts.ipv6.set_flow_label(interned.label);
            // A caller that asked the kernel to choose learns which label it
            // got by reading the field back.
            if req.label == 0 {
                let mut out = req;
                out.label = interned.label;
                let bytes = out.encode();
                let _ = uaccess::copy_to_user(optval, &bytes);
            }
            0
        }
        _ => errno(Errno::Einval),
    }
}

fn now_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// A label is a twenty-bit field, so the clock is entropy enough: a collision
/// only costs the table one more attempt. # C: O(1)
fn pick_label() -> u32 { (now_ns() as u32).rotate_left(7) }

fn owner_identity() -> flowlabel::Owner {
    let Some(task) = sched::live::current() else { return flowlabel::Owner::default(); };
    flowlabel::Owner {
        pid: task.tgid.load(Ordering::Acquire) as u32,
        uid: task.creds.euid.load(Ordering::Acquire),
    }
}

/// `IPV6_MULTICAST_IF`. # C: O(ifaces)
fn set_multicast_if(sock: &Arc<InetSocket>, val: i32, optlen: u32,
                    view: v6set::Ipv6Sock) -> i64 {
    let requested = match v6set::multicast_if_request(val, optlen, view) {
        Ok(r) => r, Err(e) => return errno(e),
    };
    let Some(ifindex) = requested else {
        return encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Iface(0)));
    };
    let master = net::sock::iface::l3_master_index(sock.net_ns(), ifindex);
    let bound = sock.opts.bound_ifindex.load(Ordering::Acquire) as i32;
    match v6set::multicast_if_admit(ifindex, master, bound) {
        Ok(action) => apply(sock, action, val),
        Err(e) => errno(e),
    }
}

/// `IPV6_UNICAST_IF`. # C: O(ifaces)
fn set_unicast_if(sock: &Arc<InetSocket>, val: i32, optlen: u32) -> i64 {
    let requested = match v6set::unicast_if_request(val, optlen) {
        Ok(r) => r, Err(e) => return errno(e),
    };
    let Some(ifindex) = requested else { sock.opts.ipv6.set_unicast_if(0); return 0; };
    let exists = net::sock::iface::iface_exists(sock.net_ns(), ifindex);
    let bound = sock.opts.bound_ifindex.load(Ordering::Acquire) as i32;
    match v6set::unicast_if_admit(ifindex, exists, bound) {
        Ok(action) => apply(sock, action, val),
        Err(e) => errno(e),
    }
}

/// The multicast and anycast families keep their own owners. # C: O(sources)
fn delegated(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen: u32) -> i64 {
    match optname {
        IPV6_ADD_MEMBERSHIP => ipv6_mcast_membership(sock, optval, optlen, true),
        IPV6_DROP_MEMBERSHIP => ipv6_mcast_membership(sock, optval, optlen, false),
        // An anycast address is joined the same way a multicast group is: the
        // stack tracks one membership per interface and address.
        IPV6_JOIN_ANYCAST => ipv6_mcast_membership(sock, optval, optlen, true),
        IPV6_LEAVE_ANYCAST => ipv6_mcast_membership(sock, optval, optlen, false),
        MCAST_JOIN_GROUP => ipv6_mcast_group_req(sock, optval, optlen, true),
        MCAST_LEAVE_GROUP => ipv6_mcast_group_req(sock, optval, optlen, false),
        MCAST_JOIN_SOURCE_GROUP =>
            ipv6_mcast_group_source_req(sock, optval, optlen, SourceOp::Join),
        MCAST_LEAVE_SOURCE_GROUP =>
            ipv6_mcast_group_source_req(sock, optval, optlen, SourceOp::Leave),
        MCAST_BLOCK_SOURCE =>
            ipv6_mcast_group_source_req(sock, optval, optlen, SourceOp::Block),
        MCAST_UNBLOCK_SOURCE =>
            ipv6_mcast_group_source_req(sock, optval, optlen, SourceOp::Unblock),
        MCAST_MSFILTER => ipv6_group_filter(sock, optval, optlen),
        // The caller-supplied-header and checksum options reach their raw
        // owner before this table runs.
        _ => errno(Errno::Enoprotoopt),
    }
}

fn encode(result: net::NetResult<()>) -> i64 {
    match result { Ok(()) => 0, Err(error) => errno_from_neterr(error) }
}

/// Gate `IPPROTO_IPV6` options to AF_INET6 sockets. # C: O(1)
pub(super) fn require_v6(sock: &Arc<InetSocket>) -> Result<(), i64> {
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET6 {
        return Err(errno(Errno::Eafnosupport));
    }
    Ok(())
}

/// The option-area import allocates, so the vector type stays explicit.
type _Area = Vec<u8>;
