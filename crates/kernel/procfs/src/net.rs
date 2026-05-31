// /proc/net/* + /proc/modules inode impls split out of procfs.rs
// to keep that file under the 1000-line cap (docs/08§7). The
// dispatch inside procfs::lookup_dynamic remains there; only the
// per-file Inode impls live here.



use alloc::sync::Arc;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// `/proc/net/dev` — Linux text format: header + per-iface line.
pub struct ProcNetDevInode;
impl vfs::Inode for ProcNetDevInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0001 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetDevInode {
    fn body(&self) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "Inter-|   Receive                                                |  Transmit");
        let _ = writeln!(s, " face |bytes packets errs drop fifo frame compressed multicast |bytes packets errs drop fifo colls carrier compressed");
        let stack = net::sock::stack();
        let snap = stack.ifaces.snapshot();
        for (id, name, mtu) in snap {
            let stats = stack.ifaces.lookup(id).map(|d| d.stats()).unwrap_or_default();
            let _ = writeln!(s, "{:>6}: {} {} {} {} 0 0 0 0 {} {} {} {} 0 0 0 0  # mtu={}",
                name,
                stats.rx_bytes, stats.rx_packets, stats.rx_errors, stats.rx_dropped,
                stats.tx_bytes, stats.tx_packets, stats.tx_errors, stats.tx_dropped,
                mtu);
        }
        s
    }
}

/// `/proc/net/tcp` — Linux fixed-width per-connection table.
pub struct ProcNetTcpInode;
impl vfs::Inode for ProcNetTcpInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0002 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetTcpInode {
    fn body(&self) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write as _;
        use net::addr::IpAddr;
        let mut s = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
        let stack = net::sock::stack();
        let mut sl: u32 = 0;
        // LISTEN rows from the v4 listener table.
        let listens = stack.tcp_listens_map().lock();
        for (key, _) in listens.iter() {
            if let IpAddr::V4(ip) = key.local_ip {
                let ip_be = ip.as_u32().to_be();
                let _ = writeln!(s, "{:5}: {:08X}:{:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0",
                    sl, ip_be, key.local_port);
                sl += 1;
            }
        }
        drop(listens);
        // Established / other states from the conn table.
        let conns = stack.tcp_conns_map().lock();
        for (key, entry) in conns.iter() {
            let (IpAddr::V4(lip), IpAddr::V4(rip)) = (key.local_ip, key.remote_ip)
                else { continue };
            let st = linux_tcp_state(entry.conn.lock().state);
            let _ = writeln!(s, "{:5}: {:08X}:{:04X} {:08X}:{:04X} {:02X} 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0",
                sl, lip.as_u32().to_be(), key.local_port,
                rip.as_u32().to_be(), key.remote_port, st);
            sl += 1;
        }
        s
    }
}

/// Translate our internal TcpState to Linux's /proc/net/tcp values
/// (uapi/linux/tcp.h `enum tcp_state`). `ss`/`netstat` decode this.
fn linux_tcp_state(s: net::tcp_state::TcpState) -> u8 {
    use net::tcp_state::TcpState::*;
    match s {
        Established => 1,
        SynSent     => 2,
        SynRecv     => 3,
        FinWait1    => 4,
        FinWait2    => 5,
        TimeWait    => 6,
        Closed      => 7,
        CloseWait   => 8,
        LastAck     => 9,
        Listen      => 10,
        Closing     => 11,
    }
}

/// `/proc/net/udp` — UDP equivalent.
pub struct ProcNetUdpInode;
impl vfs::Inode for ProcNetUdpInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0003 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetUdpInode {
    fn body(&self) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write as _;
        let mut s = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
        );
        let stack = net::sock::stack();
        let map = stack.udp_map().lock();
        let mut sl: u32 = 0;
        // UDP local-bind table — Linux reports 0.0.0.0 for INADDR_ANY,
        // and our table is port-keyed (no per-bind IP), so we honour
        // the wildcard convention.
        for (port, _) in map.iter() {
            let _ = writeln!(s, "{:5}: 00000000:{:04X} 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 0 2 0000000000000000 0",
                sl, port);
            sl += 1;
        }
        s
    }
}

/// `/proc/modules` — Linux text format: "<name> <size> <refcnt> <holders> <state> <addr>\n".
/// v1 uses synthetic name "module_<idx>" since .modinfo parsing
/// hasn't landed.
pub struct ProcModulesInode;
impl vfs::Inode for ProcModulesInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0004 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcModulesInode {
    fn body(&self) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write as _;
        let mut s = String::new();
        for (idx, n_secs, n_syms) in modules::registry::snapshot() {
            let _ = writeln!(s, "module_{} {} {} - Live 0x0 sec={} sym={}",
                idx, n_secs * 4096, 0, n_secs, n_syms);
        }
        s
    }
}

/// `/proc/net/route` — IPv4 routing table. Linux text format:
///   Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
pub struct ProcNetRouteInode;
impl vfs::Inode for ProcNetRouteInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0005 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetRouteInode {
    fn body(&self) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write as _;
        let mut s = String::from(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
        );
        let stack = net::sock::stack();
        for re in stack.routes.snapshot() {
            let dev = stack.ifaces.lookup(re.iface);
            let iface_name = dev.as_ref().map(|d| d.name()).unwrap_or("lo");
            // Linux text encodes addrs in network-byte-order hex (LE
            // from the on-the-wire perspective).
            let dst_be = re.dst.as_u32().to_le();
            let mask = if re.prefix_len == 0 { 0u32 }
                       else { !0u32 << (32 - re.prefix_len) };
            let _ = writeln!(s,
                "{}\t{:08X}\t{:08X}\t0001\t0\t0\t0\t{:08X}\t0\t0\t0",
                iface_name, dst_be, 0u32, mask.to_le(),
            );
        }
        s
    }
}

/// `/proc/net/arp` — ARP cache table.
pub struct ProcNetArpInode;
impl vfs::Inode for ProcNetArpInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0006 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetArpInode {
    fn body(&self) -> alloc::string::String {
        // v1: empty ARP cache (loopback only). Header still
        // emitted so iproute2 + others parse without erroring.
        alloc::string::String::from(
            "IP address       HW type     Flags       HW address            Mask     Device\n",
        )
    }
}

/// `/proc/net/unix` — AF_UNIX socket table. netstat/ss/lsof
/// probe this. v1 returns header + zero rows.
pub struct ProcNetUnixInode;
impl vfs::Inode for ProcNetUnixInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0007 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetUnixInode {
    fn body(&self) -> alloc::string::String {
        alloc::string::String::from(
            "Num       RefCount Protocol Flags    Type St Inode Path\n",
        )
    }
}

/// `/proc/net/if_inet6` — IPv6 per-iface address table.
/// glibc + ifconfig probe this for V6 status. Format:
///   addr-hex(32) iface-idx(02) prefix(02) scope(02) flags(02) name
/// Loopback ::1 only for v1.
pub struct ProcNetIfInet6Inode;
impl vfs::Inode for ProcNetIfInet6Inode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0008 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetIfInet6Inode {
    fn body(&self) -> alloc::string::String {
        // ::1 loopback, idx 1, /128, scope=host(0x10), flags=permanent(0x80).
        alloc::string::String::from(
            "00000000000000000000000000000001 01 80 10 80 lo\n",
        )
    }
}

/// `/proc/net/snmp` — protocol-level counters. netstat -s probes
/// this. v1 returns just the header rows; counters all zero.
pub struct ProcNetSnmpInode;
impl vfs::Inode for ProcNetSnmpInode {
    fn ino(&self) -> vfs::Ino { 0xFEED_0009 }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.body().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let body = self.body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body.as_bytes()[off..off+n]);
        Ok(n)
    }
}

impl ProcNetSnmpInode {
    fn body(&self) -> alloc::string::String {
        alloc::string::String::from(
            "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates\n\
             Ip: 1 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
             Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
             Icmp: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
             Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
             Tcp: 1 200 120000 -1 0 0 0 0 0 0 0 0 0 0 0\n\
             Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n\
             Udp: 0 0 0 0 0 0 0 0\n",
        )
    }
}
