// /proc/net/* + /proc/modules inode impls split out of procfs.rs
// to keep that file under the 1000-line cap (docs/08§7). The
// dispatch inside procfs::lookup_dynamic remains there; only the
// per-file Inode impls live here.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

use alloc::sync::Arc;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// `/proc/net/dev` — Linux text format: header + per-iface line.
pub(crate) struct ProcNetDevInode;
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
        let stack = crate::dev_net::stack();
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
pub(crate) struct ProcNetTcpInode;
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
        // v1 surfaces just the header; per-connection rows ride
        // alongside a Stack::tcp_conns_snapshot() helper. The
        // shape lets `ss -t` parse without erroring on empty.
        alloc::string::String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
    }
}

/// `/proc/net/udp` — UDP equivalent.
pub(crate) struct ProcNetUdpInode;
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
        alloc::string::String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
        )
    }
}

/// `/proc/modules` — Linux text format: "<name> <size> <refcnt> <holders> <state> <addr>\n".
/// v1 uses synthetic name "module_<idx>" since .modinfo parsing
/// hasn't landed.
pub(crate) struct ProcModulesInode;
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
        for (idx, n_secs, n_syms) in crate::dev_modules::snapshot() {
            let _ = writeln!(s, "module_{} {} {} - Live 0x0 sec={} sym={}",
                idx, n_secs * 4096, 0, n_secs, n_syms);
        }
        s
    }
}

/// `/proc/net/route` — IPv4 routing table. Linux text format:
///   Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
pub(crate) struct ProcNetRouteInode;
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
        let stack = crate::dev_net::stack();
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
pub(crate) struct ProcNetArpInode;
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
