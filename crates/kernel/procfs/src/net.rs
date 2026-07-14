// /proc/net/* + /proc/modules inode bodies split out of procfs.rs
// to keep that file under the 1000-line cap (docs/08§7). KEYSTONE
// struct-`Inode` model: each file is a `vfs::Inode` built by
// `dyn_file::make_gen_file` over the per-file body generator below.

use alloc::string::String;
use vfs::{Ino, InodeRef};

/// `/proc/net/dev` — Linux text format: header + per-iface line.
fn net_dev_body() -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Inter-|   Receive                                                |  Transmit");
    let _ = writeln!(s, " face |bytes packets errs drop fifo frame compressed multicast |bytes packets errs drop fifo colls carrier compressed");
    let stack = net::sock::stack();
    let snap = stack.ifaces.snapshot_in_ns(net::netdev::current_net_ns());
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
pub fn make_proc_net_dev() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0001 as Ino, net_dev_body) }

/// `/proc/net/tcp` — Linux fixed-width per-connection table.
fn net_tcp_body() -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    use net::addr::IpAddr;
    let mut s = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    let stack = net::sock::stack();
    let mut sl: u32 = 0;
    for row in stack.inet_diag_snapshot_in(net::netdev::current_net_ns(), 6) {
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
pub fn make_proc_net_tcp() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0002 as Ino, net_tcp_body) }

/// `/proc/net/tcp6` — IPv6 TCP table matching Linux tcp6 column shape.
fn net_tcp6_body() -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    use net::addr::IpAddr;

    let mut s = String::from(
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    let stack = net::sock::stack();
    let mut sl: u32 = 0;
    for row in stack.inet_diag_snapshot_in(net::netdev::current_net_ns(), 6) {
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
pub fn make_proc_net_tcp6() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_000A as Ino, net_tcp6_body) }

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
fn net_udp_body() -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
    );
    let stack = net::sock::stack();
    let mut sl: u32 = 0;
    for row in stack.inet_diag_snapshot_in(net::netdev::current_net_ns(), 17) {
        if let net::addr::IpAddr::V4(ip) = row.local_ip {
            let _ = writeln!(s, "{:5}: {:08X}:{:04X} 00000000:0000 07 00000000:{:08X} 00:00000000 00000000     0        0 0 2 0000000000000000 0",
                sl, ip.as_u32().to_be(), row.local_port, row.rqueue);
            sl += 1;
        }
    }
    s.into_bytes()
}
/// `/proc/net/udp` inode. # C: O(1)
pub fn make_proc_net_udp() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0003 as Ino, net_udp_body) }

/// `/proc/net/udp6` — live IPv6 UDP bind table.
fn net_udp6_body() -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    use net::addr::Ipv6Addr;
    let mut s = String::from(
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
    );
    let stack = net::sock::stack();
    let mut sl: u32 = 0;
    for row in stack.inet_diag_snapshot_in(net::netdev::current_net_ns(), 17) {
        if let net::addr::IpAddr::V6(ip) = row.local_ip {
            let _ = writeln!(s, "{:5}: {}:{:04X} {}:0000 07 00000000:{:08X} 00:00000000 00000000     0        0 0 2 0000000000000000 0",
                sl, proc_ipv6_hex(ip), row.local_port, proc_ipv6_hex(Ipv6Addr::ANY), row.rqueue);
            sl += 1;
        }
    }
    s.into_bytes()
}
/// `/proc/net/udp6` inode. # C: O(1)
pub fn make_proc_net_udp6() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_000B as Ino, net_udp6_body) }

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
pub fn make_proc_modules() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0004 as Ino, modules_body) }

/// `/proc/net/route` — IPv4 routing table. Linux text format:
///   Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
fn net_route_body() -> alloc::vec::Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
    );
    let stack = net::sock::stack();
    let ifaces = stack.ifaces.snapshot();
    for re in stack.routes.snapshot() {
        let Some(iface) = ifaces.iter().find(|i| i.id == re.iface) else { continue };
        // Linux text encodes addrs in network-byte-order hex (LE
        // from the on-the-wire perspective).
        let dst_be = re.dst.as_u32().to_le();
        let mask = if re.prefix_len == 0 { 0u32 }
                   else { !0u32 << (32 - re.prefix_len) };
        let _ = writeln!(s,
            "{}\t{:08X}\t{:08X}\t0001\t0\t0\t0\t{:08X}\t0\t0\t0",
            iface.name, dst_be, 0u32, mask.to_le(),
        );
    }
    s.into_bytes()
}
/// `/proc/net/route` inode. # C: O(1)
pub fn make_proc_net_route() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0005 as Ino, net_route_body) }

/// `/proc/net/arp` — ARP cache table.
fn net_arp_body() -> alloc::vec::Vec<u8> {
    // v1: empty ARP cache (loopback only). Header still
    // emitted so iproute2 + others parse without erroring.
    b"IP address       HW type     Flags       HW address            Mask     Device\n".to_vec()
}
/// `/proc/net/arp` inode. # C: O(1)
pub fn make_proc_net_arp() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0006 as Ino, net_arp_body) }

/// `/proc/net/unix` — AF_UNIX socket table. netstat/ss/lsof
/// probe this. v1 returns header + zero rows.
fn net_unix_body() -> alloc::vec::Vec<u8> {
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
    // B518: `/proc/net/unix` reflects the reader's net_ns (id 0 = the
    // untouched global registry).
    let mut line = String::new();
    for (kind, path) in net::net_ns::current_unix_registry().snapshot_paths() {
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
pub fn make_proc_net_unix() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0007 as Ino, net_unix_body) }

/// `/proc/net/if_inet6` — IPv6 per-iface address table.
/// glibc + ifconfig probe this for V6 status. Format:
///   addr-hex(32) iface-idx(02) prefix(02) scope(02) flags(02) name
/// Loopback ::1 only for v1.
fn net_if_inet6_body() -> alloc::vec::Vec<u8> {
    // ::1 loopback, idx 1, /128, scope=host(0x10), flags=permanent(0x80).
    b"00000000000000000000000000000001 01 80 10 80 lo\n".to_vec()
}
/// `/proc/net/if_inet6` inode. # C: O(1)
pub fn make_proc_net_if_inet6() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0008 as Ino, net_if_inet6_body) }

/// `/proc/net/snmp` — protocol-level counters. netstat -s probes
/// this. v1 returns just the header rows; counters all zero.
fn net_snmp_body() -> alloc::vec::Vec<u8> {
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
pub fn make_proc_net_snmp() -> InodeRef { crate::dyn_file::make_gen_file(0xFEED_0009 as Ino, net_snmp_body) }
