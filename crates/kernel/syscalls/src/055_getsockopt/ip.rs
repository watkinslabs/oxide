// `IPPROTO_IP` readback copyout for slot 55. The value table and its length
// rules live in `net::sock_opts::sol_ip::get` (`docs/53§4`); this file only
// snapshots socket state and moves bytes.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use net::sock::InetSocket;
use net::sock_opts::sol_ip::get::{self as ipget, IpGetState, ScalarOut, Value};
use net::sock_opts::sol_ip::uapi::*;

use super::multicast::{ipv4_group_filter_get, ipv4_msfilter_get, scalar_get};
use super::out::OptOut;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Snapshot the socket state the read table resolves against. # C: O(optlen)
fn view(sock: &Arc<InetSocket>) -> IpGetState {
    use net::sock::SockKind;
    use net::sock_opts::sol_ip::flag;
    let hdrincl = match &*sock.kind.lock() {
        SockKind::Raw4(endpoint) => endpoint.hdrincl(),
        _ => false,
    };
    let mut flags = sock.opts.ip.flag_word();
    // Unconditional multicast delivery lives on the shared membership object,
    // which is what the receive path consults.
    if sock.mcast.multicast_all_v4() { flags &= !flag::MC_ALL_OFF; }
    else { flags |= flag::MC_ALL_OFF; }
    IpGetState {
        flags,
        pktinfo: sock.opts.ip_pktinfo.load(Ordering::Acquire) != 0,
        recvttl: sock.opts.ip_recvttl.load(Ordering::Acquire) != 0,
        recverr: sock.error.recverr4(),
        hdrincl,
        mc_loop: sock.opts.ip_mcast_loop.load(Ordering::Acquire) != 0,
        ttl: sock.opts.ip_ttl.load(Ordering::Acquire),
        default_ttl: net::ipv4::IPV4_DEFAULT_TTL as i32,
        min_ttl: sock.opts.min_hop.ttl(),
        mcast_ttl: sock.opts.ip_mcast_ttl.load(Ordering::Acquire),
        tos: sock.opts.ip_tos.load(Ordering::Acquire),
        pmtudisc: sock.opts.ip_mtu_discover.load(Ordering::Acquire),
        unicast_if: sock.opts.ip.unicast_if(),
        local_port_range: sock.opts.ip.local_port_range(),
        options: sock.opts.ip.options_undone(),
        mcast_addr: net::Ipv4Addr::from_u32(
            sock.opts.ip_mcast_ifaddr.load(Ordering::Acquire)).octets(),
        // Only the path-MTU read consults a route, and it owns its own copyout.
        mtu: 0,
    }
}

/// `getsockopt(fd, IPPROTO_IP, ...)`. # C: O(optlen)
pub(super) fn get(sock: &Arc<InetSocket>, optname: u64, out: &OptOut) -> i64 {
    // The multicast reads own their whole copyout.
    match optname {
        IP_MSFILTER => return ipv4_msfilter_get(sock, out.optval, out.optlen_p),
        MCAST_MSFILTER => return ipv4_group_filter_get(sock, out.optval, out.optlen_p),
        IP_MULTICAST_TTL =>
            return scalar_get(sock, net::sock_mcast::McastScalarGet::V4Ttl, out),
        IP_MULTICAST_LOOP =>
            return scalar_get(sock, net::sock_mcast::McastScalarGet::V4Loop, out),
        IP_MTU => return super::path_mtu::socket_path_mtu(sock, false, out),
        _ => {}
    }
    let value = match ipget::read(optname, net::sock_opts::describe_ip(sock), &view(sock)) {
        Ok(v) => v, Err(e) => return errno(e),
    };
    if value == Value::ControlStream { return pktoptions_get(sock, out); }
    publish(out, value)
}

/// `IP_PKTOPTIONS`: the ancillary messages a stream socket publishes on
/// demand, encoded into the caller's buffer. A message that does not fit whole
/// is not written at all. # C: O(messages)
fn pktoptions_get(sock: &Arc<InetSocket>, out: &OptOut) -> i64 {
    let requested = match requested(out.optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    let want = net::cmsg::Want {
        pktinfo: sock.opts.ip_pktinfo.load(Ordering::Acquire) != 0,
        ttl: sock.opts.ip_recvttl.load(Ordering::Acquire) != 0,
        tos: sock.opts.ip.flag(net::sock_opts::sol_ip::flag::RECVTOS),
        ..Default::default()
    };
    let rx = net::cmsg::pktoptions::StreamRx {
        saddr: sock.local_ip.lock().octets(),
        ifindex: sock.opts.ip_mcast_ifindex.load(Ordering::Acquire),
        ttl: sock.opts.ip_mcast_ttl.load(Ordering::Acquire),
        tos: sock.opts.ip_rcv_tos.load(Ordering::Acquire),
    };
    let mut control = crate::recv_control::Control::new(requested as usize);
    for msg in net::cmsg::pktoptions::plan(&want, &rx) {
        control.push(msg.level, msg.kind, &msg.bytes);
    }
    out.exact(&control.to_bytes())
}

fn publish(out: &OptOut, value: Value) -> i64 {
    let requested = match requested(out.optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    match value {
        Value::Int(v) => match ipget::scalar_out(v, requested) {
            ScalarOut::Byte(b) => out.exact(&[b]),
            ScalarOut::Int(len) => out.exact(&v.to_ne_bytes()[..len]),
        },
        Value::Bytes(bytes) => {
            let len = ipget::bytes_len(bytes.len(), requested);
            out.exact(&bytes[..len])
        }
        Value::Delegated | Value::ControlStream => errno(Errno::Enoprotoopt),
    }
}

fn requested(optlen_p: u64) -> Result<i32, Errno> {
    let mut raw = [0u8; 4];
    uaccess::copy_from_user(&mut raw, optlen_p).map_err(|_| Errno::Efault)?;
    let value = i32::from_ne_bytes(raw);
    if value < 0 { return Err(Errno::Einval); }
    Ok(value)
}
