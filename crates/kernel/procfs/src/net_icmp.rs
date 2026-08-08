// `/proc/net/icmp{,6}` — the ICMP datagram endpoints one network namespace
// publishes. The local port column is the kernel-assigned echo identifier, and
// the remote port is always zero because this endpoint class has no ports.
// Raw ICMP sockets stay in `/proc/net/raw{,6}`; the two exports never overlap.

use alloc::string::String;
use core::fmt::Write as _;
use net::addr::IpAddr;
use vfs::{Ino, InodeRef};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const HEADER_V4: &str =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";
const HEADER_V6: &str =
    "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";

fn icmp_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    let mut out = String::from(HEADER_V4);
    let mut sl: u32 = 0;
    for row in net::global_stack().ping_diag_snapshot_in(net_ns, AF_INET) {
        if let (IpAddr::V4(local), IpAddr::V4(remote)) = (row.local_ip, row.remote_ip) {
            let _ = writeln!(out, "{:5}: {:08X}:{:04X} {:08X}:0000 07 00000000:{:08X} 00:00000000 00000000     0        0 0 2 0000000000000000 {}",
                sl, local.as_u32().to_be(), row.ident, remote.as_u32().to_be(), row.rqueue, row.drops);
            sl += 1;
        }
    }
    out.into_bytes()
}

fn icmp6_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    let mut out = String::from(HEADER_V6);
    let mut sl: u32 = 0;
    for row in net::global_stack().ping_diag_snapshot_in(net_ns, AF_INET6) {
        if let (IpAddr::V6(local), IpAddr::V6(remote)) = (row.local_ip, row.remote_ip) {
            let _ = writeln!(out, "{:5}: {}:{:04X} {}:0000 07 00000000:{:08X} 00:00000000 00000000     0        0 0 2 0000000000000000 {}",
                sl, crate::net_raw::ipv6_hex(local), row.ident, crate::net_raw::ipv6_hex(remote),
                row.rqueue, row.drops);
            sl += 1;
        }
    }
    out.into_bytes()
}

/// `/proc/net/icmp` namespace-relative immutable-snapshot inode. # C: O(1)
pub fn make_proc_net_icmp() -> InodeRef {
    crate::dyn_file::make_ns_gen_file(crate::ids::NET_ICMP as Ino,
        net::netdev::current_net_ns, icmp_body)
}

/// `/proc/net/icmp6` namespace-relative immutable-snapshot inode. # C: O(1)
pub fn make_proc_net_icmp6() -> InodeRef {
    crate::dyn_file::make_ns_gen_file(crate::ids::NET_ICMP6 as Ino,
        net::netdev::current_net_ns, icmp6_body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    fn ping4(namespace: network_namespace::NetworkNamespaceRef)
        -> Arc<net::raw4::Raw4Endpoint>
    {
        net::raw4::Raw4Endpoint::new_ping(net::SocketOwner::root(namespace, 0),
            Arc::new(net::bpf_filter::SocketFilter::new()),
            Arc::new(net::mcast_filter::SocketMcast::new()),
            Arc::new(net::SocketError::new()),
            Arc::new(core::sync::atomic::AtomicI32::new(0)),
            Arc::new(core::sync::atomic::AtomicI32::new(net::uapi::IP_PMTUDISC_WANT)),
            Arc::new(net::sock_opts::sol_ip::IpOpts::default()))
    }

    // The identifier is the local port column, and a raw ICMP socket in the
    // same namespace never appears here — the two exports own disjoint sets.
    #[test]
    fn icmp_export_lists_endpoints_by_their_kernel_identifier() {
        let _ = net::net_ns::install_final_drop_pending_notifier();
        let namespace = network_namespace::allocate(namespace_identity::initial(
            namespace_identity::NamespaceKind::User)).unwrap();
        net::net_ns::materialize_state(&namespace);
        let ns = namespace.id().as_u64();
        assert_eq!(icmp_body(ns), HEADER_V4.as_bytes().to_vec());

        let endpoint = ping4(namespace.clone());
        net::ping::bind_v4(&endpoint, 0x1234).unwrap();
        endpoint.bind(net::Ipv4Addr::new(10, 0, 0, 7), None).unwrap();
        let text = String::from_utf8(icmp_body(ns)).unwrap();
        assert!(text.contains("0700000A:1234"), "unexpected body: {text}");
        assert!(text.contains(":0000 07 "), "the remote port column is always zero: {text}");

        let raw = net::raw4::Raw4Endpoint::new(net::addr::IpProto::Icmp as u8, namespace,
            Arc::new(net::bpf_filter::SocketFilter::new()),
            Arc::new(net::mcast_filter::SocketMcast::new()),
            Arc::new(net::SocketError::new()));
        net::global_stack().register_raw4(&raw);
        assert_eq!(String::from_utf8(icmp_body(ns)).unwrap().lines().count(), 2,
            "a raw ICMP socket belongs to the raw export, not this one");
        net::global_stack().unregister_raw4(&raw);
    }
}
