// /proc/net/* + /proc/modules inode bodies split out of procfs.rs
// to keep that file under the 1000-line cap (docs/08§7). KEYSTONE
// struct-`Inode` model: each file is a `vfs::Inode` built by
// `dyn_file::make_ns_gen_file` over the per-file body generator below.

use alloc::string::String;
use crate::ids;
use vfs::{Ino, InodeRef};

/// `/proc/net/dev` — Linux text format: header + per-iface line.
fn net_dev_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Inter-|   Receive                                                |  Transmit");
    let _ = writeln!(s, " face |bytes packets errs drop fifo frame compressed multicast |bytes packets errs drop fifo colls carrier compressed");
    let stack = net::sock::stack();
    let snap = stack.ifaces.snapshot_in_ns(net_ns);
    for iface in snap {
        let stats = iface.stats;
        let _ = writeln!(s, "{:>6}: {} {} {} {} 0 0 0 0 {} {} {} {} 0 0 0 0  # mtu={}",
            iface.name,
            stats.rx_bytes, stats.rx_packets, stats.rx_errors, stats.rx_dropped,
            stats.tx_bytes, stats.tx_packets, stats.tx_errors, stats.tx_dropped,
            iface.mtu);
    }
    s.into_bytes()
}
/// `/proc/net/dev` inode. # C: O(1)
pub fn make_proc_net_dev() -> InodeRef { make_net_file(ids::NET_DEV as Ino, net_dev_body) }

/// `/proc/net/tcp` — Linux fixed-width per-connection table.
fn net_tcp_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    use net::addr::IpAddr;
    let mut s = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    let stack = net::sock::stack();
    let mut sl: u32 = 0;
    for row in stack.inet_diag_snapshot_in(net_ns, 6) {
        if let (IpAddr::V4(ip), IpAddr::V4(remote)) = (row.local_ip, row.remote_ip) {
            let ip_be = ip.as_u32().to_be();
            let _ = writeln!(s, "{:5}: {:08X}:{:04X} {:08X}:{:04X} {:02X} 00000000:{:08X} 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0",
                sl, ip_be, row.local_port, remote.as_u32().to_be(), row.remote_port,
                row.state, row.rqueue);
            sl += 1;
        }
    }
    s.into_bytes()
}
/// `/proc/net/tcp` inode. # C: O(1)
pub fn make_proc_net_tcp() -> InodeRef { make_net_file(ids::NET_TCP as Ino, net_tcp_body) }

/// `/proc/net/tcp6` — IPv6 TCP table matching Linux tcp6 column shape.
fn net_tcp6_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    use net::addr::IpAddr;

    let mut s = String::from(
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    let stack = net::sock::stack();
    let mut sl: u32 = 0;
    for row in stack.inet_diag_snapshot_in(net_ns, 6) {
        if let (IpAddr::V6(local), IpAddr::V6(remote)) = (row.local_ip, row.remote_ip) {
            let _ = writeln!(s, "{:5}: {}:{:04X} {}:{:04X} {:02X} 00000000:{:08X} 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0",
                sl, proc_ipv6_hex(local), row.local_port, proc_ipv6_hex(remote),
                row.remote_port, row.state, row.rqueue);
            sl += 1;
        }
    }
    s.into_bytes()
}
/// `/proc/net/tcp6` inode. # C: O(1)
pub fn make_proc_net_tcp6() -> InodeRef { make_net_file(ids::NET_TCP6 as Ino, net_tcp6_body) }

/// Translate our internal TcpState to Linux's /proc/net/tcp values
/// (uapi/linux/tcp.h `enum tcp_state`). `ss`/`netstat` decode this.
fn proc_ipv6_hex(ip: net::addr::Ipv6Addr) -> alloc::string::String {
    use alloc::format;
    let o = ip.0;
    let a = u32::from_be_bytes([o[0], o[1], o[2], o[3]]).to_be();
    let b = u32::from_be_bytes([o[4], o[5], o[6], o[7]]).to_be();
    let c = u32::from_be_bytes([o[8], o[9], o[10], o[11]]).to_be();
    let d = u32::from_be_bytes([o[12], o[13], o[14], o[15]]).to_be();
    format!("{a:08X}{b:08X}{c:08X}{d:08X}")
}

/// `/proc/net/udp` — UDP equivalent.
fn net_udp_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
    );
    let stack = net::sock::stack();
    let mut sl: u32 = 0;
    for row in stack.inet_diag_snapshot_in(net_ns, 17) {
        if let net::addr::IpAddr::V4(ip) = row.local_ip {
            let _ = writeln!(s, "{:5}: {:08X}:{:04X} 00000000:0000 07 00000000:{:08X} 00:00000000 00000000     0        0 0 2 0000000000000000 0",
                sl, ip.as_u32().to_be(), row.local_port, row.rqueue);
            sl += 1;
        }
    }
    s.into_bytes()
}
/// `/proc/net/udp` inode. # C: O(1)
pub fn make_proc_net_udp() -> InodeRef { make_net_file(ids::NET_UDP as Ino, net_udp_body) }

/// `/proc/net/udp6` — live IPv6 UDP bind table.
fn net_udp6_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    use net::addr::Ipv6Addr;
    let mut s = String::from(
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
    );
    let stack = net::sock::stack();
    let mut sl: u32 = 0;
    for row in stack.inet_diag_snapshot_in(net_ns, 17) {
        if let net::addr::IpAddr::V6(ip) = row.local_ip {
            let _ = writeln!(s, "{:5}: {}:{:04X} {}:0000 07 00000000:{:08X} 00:00000000 00000000     0        0 0 2 0000000000000000 0",
                sl, proc_ipv6_hex(ip), row.local_port, proc_ipv6_hex(Ipv6Addr::ANY), row.rqueue);
            sl += 1;
        }
    }
    s.into_bytes()
}
/// `/proc/net/udp6` inode. # C: O(1)
pub fn make_proc_net_udp6() -> InodeRef { make_net_file(ids::NET_UDP6 as Ino, net_udp6_body) }

/// `/proc/modules` — Linux text format plus audit fields for parsed module metadata.
fn modules_body() -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::new();
    for m in modules::registry::snapshot() {
        let license = m.license.as_deref().unwrap_or("-");
        let vermagic = m.vermagic.as_deref().unwrap_or("-");
        let _ = writeln!(s, "{} {} {} - {} 0x0 sec={} sym={} taint=0x{:x} license={} vermagic={} params={}",
            m.name, m.size, m.refcnt, m.state.as_str(), m.sections, m.symbols,
            m.taints, license, vermagic, m.params.len());
    }
    s.into_bytes()
}
/// `/proc/modules` inode. # C: O(1)
pub fn make_proc_modules() -> InodeRef { crate::dyn_file::make_gen_file(ids::MODULES as Ino, modules_body) }

/// `/proc/net/route` — IPv4 routing table. Linux text format:
///   Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
fn net_route_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
    );
    let stack = net::sock::stack();
    let ifaces = stack.ifaces.snapshot_in_ns(net_ns);
    for record in stack.routes.snapshot_records_in(net_ns) {
        let re = record.route;
        if re.table != net::policy_rule::RT_TABLE_MAIN { continue; }
        let Some(iface) = ifaces.iter().find(|i| i.id == re.iface) else { continue };
        // Linux text encodes addrs in network-byte-order hex (LE
        // from the on-the-wire perspective).
        let dst_be = re.dst.as_u32().to_le();
        let mask = if re.prefix_len == 0 { 0u32 }
                   else { !0u32 << (32 - re.prefix_len) };
        let gateway = re.gateway.map(|ip| ip.as_u32().to_le()).unwrap_or(0);
        let mut flags = 0x0001u16;
        if re.gateway.is_some() { flags |= 0x0002; }
        if re.prefix_len == 32 { flags |= 0x0004; }
        let _ = writeln!(s,
            "{}\t{:08X}\t{:08X}\t{:04X}\t0\t0\t{}\t{:08X}\t{}\t0\t0",
            iface.name, dst_be, gateway, flags, record.metric, mask.to_le(),
            record.mtu.unwrap_or(0),
        );
    }
    s.into_bytes()
}
/// `/proc/net/route` inode. # C: O(1)
pub fn make_proc_net_route() -> InodeRef { make_net_file(ids::NET_ROUTE as Ino, net_route_body) }

/// `/proc/net/arp` — ARP cache table.
fn net_arp_body(_net_ns: u64) -> alloc::vec::Vec<u8> {
    // v1: empty ARP cache (loopback only). Header still
    // emitted so iproute2 + others parse without erroring.
    b"IP address       HW type     Flags       HW address            Mask     Device\n".to_vec()
}
/// `/proc/net/arp` inode. # C: O(1)
pub fn make_proc_net_arp() -> InodeRef { make_net_file(ids::NET_ARP as Ino, net_arp_body) }

/// `/proc/net/unix` — AF_UNIX socket table. netstat/ss/lsof
/// probe this. v1 returns header + zero rows.
fn net_unix_body(net_ns: u64) -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    let mut out = String::from(
        "Num       RefCount Protocol Flags    Type St Inode Path\n",
    ).into_bytes();
    // Each entry: opaque "Num" (we use a stable per-row counter),
    // RefCount 02, Protocol 0, Flags 0x10000 for stream listeners
    // (LISTENING) / 0 otherwise, Type (0001 stream | 0002 dgram),
    // St 01 (UNCONNECTED for listener / bound dgram), Inode 0
    // (no inode table linkage), Path.
    let mut num: u64 = 1;
    let mut line = String::new();
    for (kind, path) in net::net_ns::ns_unix_registry(net_ns).snapshot_paths() {
        let flags = if kind == 0x0001 { 0x10000u32 } else { 0u32 };
        let path = net::unix_path_display(&path);
        line.clear();
        let _ = write!(line, "{:016x}: 00000002 00000000 {:08x} {:04x} 01 0 ",
            num, flags, kind);
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(&path);
        out.push(b'\n');
        num += 1;
    }
    out
}
/// `/proc/net/unix` inode. # C: O(1)
pub fn make_proc_net_unix() -> InodeRef { make_net_file(ids::NET_UNIX as Ino, net_unix_body) }

/// `/proc/net/if_inet6` — IPv6 per-iface address table.
/// glibc + ifconfig probe this for V6 status. Format:
///   addr-hex(32) iface-idx(02) prefix(02) scope(02) flags(02) name
/// Loopback ::1 only for v1.
fn net_if_inet6_body(_net_ns: u64) -> alloc::vec::Vec<u8> {
    // ::1 loopback, idx 1, /128, scope=host(0x10), flags=permanent(0x80).
    b"00000000000000000000000000000001 01 80 10 80 lo\n".to_vec()
}
/// `/proc/net/if_inet6` inode. # C: O(1)
pub fn make_proc_net_if_inet6() -> InodeRef { make_net_file(ids::NET_IF_INET6 as Ino, net_if_inet6_body) }

/// `/proc/net/snmp` — protocol-level counters. netstat -s probes
/// this. v1 returns just the header rows; counters all zero.
fn net_snmp_body(_net_ns: u64) -> alloc::vec::Vec<u8> {
    (b"Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates\n\
         Ip: 1 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
         Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
         Icmp: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
         Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
         Tcp: 1 200 120000 -1 0 0 0 0 0 0 0 0 0 0 0\n\
         Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n\
         Udp: 0 0 0 0 0 0 0 0\n" as &[u8]).to_vec()
}
/// `/proc/net/snmp` inode. # C: O(1)
pub fn make_proc_net_snmp() -> InodeRef { make_net_file(ids::NET_SNMP as Ino, net_snmp_body) }

fn make_net_file(ino: Ino, gen: fn(u64) -> alloc::vec::Vec<u8>) -> InodeRef {
    crate::dyn_file::make_ns_gen_file(ino, net::netdev::current_net_ns, gen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn route_projection_is_namespace_scoped() {
        const NS_A: u64 = 9181;
        const NS_B: u64 = 9182;
        let stack = net::global_stack();
        let iface_a = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS_A);
        let iface_b = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS_B);
        stack.routes.add_in(NS_A, net::RouteEntry {
            table: net::policy_rule::RT_TABLE_MAIN,
            dst: net::Ipv4Addr::new(10, 77, 0, 0), prefix_len: 16,
            iface: iface_a, gateway: Some(net::Ipv4Addr::new(10, 77, 0, 1)), src_hint: None,
        });
        stack.routes.add_in(NS_B, net::RouteEntry {
            table: net::policy_rule::RT_TABLE_MAIN,
            dst: net::Ipv4Addr::new(10, 88, 0, 0), prefix_len: 16,
            iface: iface_b, gateway: None, src_hint: None,
        });
        stack.routes.add_in(NS_A, net::RouteEntry {
            table: net::policy_rule::RT_TABLE_MAIN,
            dst: net::Ipv4Addr::new(10, 77, 0, 9), prefix_len: 32,
            iface: iface_a, gateway: None, src_hint: None,
        });
        stack.routes.add_in(NS_A, net::RouteEntry {
            table: 1001, dst: net::Ipv4Addr::new(10, 99, 0, 0), prefix_len: 16,
            iface: iface_a, gateway: None, src_hint: None,
        });
        let a = core::str::from_utf8(&net_route_body(NS_A)).unwrap().to_string();
        let b = core::str::from_utf8(&net_route_body(NS_B)).unwrap().to_string();
        assert!(a.contains("00004D0A"));
        assert!(!a.contains("0000580A"));
        assert!(a.contains("01004D0A"));
        assert!(a.lines().any(|line| line.contains("09004D0A") && line.contains("\t0005\t")));
        assert!(!a.contains("0000630A"));
        assert!(b.contains("0000580A"));
        assert!(!b.contains("00004D0A"));
        assert_eq!(stack.routes.remove_matching_in(NS_A, |_| true), 3);
        assert_eq!(stack.routes.remove_matching_in(NS_B, |_| true), 1);
    }
}
