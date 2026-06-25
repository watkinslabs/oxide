// NDP — IPv6 Neighbor Discovery Protocol per RFC 4861. The
// in-band ICMPv6 messages (NS=135, NA=136) replace ARP for v6.
// v1 implements:
//   - Neighbor Solicitation (target_ip in question, src->llt)
//   - Neighbor Advertisement (target_ip + flags + target_lladdr)
//   - Router Advertisement prefix parsing for SLAAC
//
// Each NS/NA carries a Type-Length-Value option list. The
// `target_lladdr` option (T=2) is the Ethernet MAC; v1 emits +
// parses just that one type for NS/NA. RA parsing consumes Prefix
// Information options so the stack can autoconfigure an address.

extern crate alloc;
use alloc::collections::BTreeMap;

use sync::{Spinlock, Socket as NdpLockClass};

use crate::addr::{Ipv6Addr, MacAddr};
use crate::ipv4::ip_checksum;
use crate::icmpv6::IPPROTO_ICMPV6;

pub const NDP_NS: u8 = 135;
pub const NDP_NA: u8 = 136;
pub const NDP_RA: u8 = 134;
pub const NDP_OPT_SOURCE_LLADDR: u8 = 1;
pub const NDP_OPT_TARGET_LLADDR: u8 = 2;
pub const NDP_OPT_PREFIX_INFO: u8 = 3;

/// 24-byte fixed body for NS / NA after the 4-byte ICMPv6
/// header words. Type 135/136, code 0, then header[4..8] = flags
/// (NA only — bits R/S/O), header[8..24] = target_ip.
pub const NDP_HDR_FIXED: usize = 24;
pub const NDP_RA_FIXED: usize = 16;

pub const NDP_PIO_FLAG_ONLINK: u8 = 0x80;
pub const NDP_PIO_FLAG_AUTO: u8 = 0x40;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NdpError { Short, BadChecksum, BadType }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NdpMsg {
    pub typ:     u8,
    pub flags:   u32,    // NA bits in low byte (R/S/O)
    pub target:  Ipv6Addr,
    pub lladdr:  Option<MacAddr>,  // option ICMPv6 source/target lladdr
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PrefixInfo {
    pub prefix_len: u8,
    pub flags: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix: Ipv6Addr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouterAdvertisement {
    pub hop_limit: u8,
    pub flags: u8,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub source_lladdr: Option<MacAddr>,
    pub prefixes: alloc::vec::Vec<PrefixInfo>,
}

impl NdpMsg {
    /// Build an NS for `target_ip`. `our_mac` populates the
    /// source-lladdr option (T=1).
    /// # C: O(1)
    pub fn build_ns(src: Ipv6Addr, dst: Ipv6Addr,
                     our_mac: MacAddr, target_ip: Ipv6Addr)
        -> alloc::vec::Vec<u8>
    {
        let total = NDP_HDR_FIXED + 8;  // body + 8-byte option (T=1)
        let mut buf = alloc::vec![0u8; total];
        buf[0] = NDP_NS;
        buf[1] = 0;
        buf[2] = 0; buf[3] = 0;  // checksum
        // reserved [4..8] = 0
        buf[8..24].copy_from_slice(&target_ip.0);
        // Option: T=1 source-lladdr, len=1 (8 bytes), MAC
        buf[24] = NDP_OPT_SOURCE_LLADDR;
        buf[25] = 1;
        buf[26..32].copy_from_slice(&our_mac.0);
        let cs = compute_ndp_checksum(&buf, src, dst);
        buf[2..4].copy_from_slice(&cs.to_be_bytes());
        buf
    }

    /// Build an NA in response to an NS. Sets the S (solicited)
    /// bit and includes the target-lladdr option. `flags_so` lets
    /// the caller toggle Override (O=0x20000000).
    /// # C: O(1)
    pub fn build_na(src: Ipv6Addr, dst: Ipv6Addr,
                     our_mac: MacAddr, target_ip: Ipv6Addr, flags_so: u32)
        -> alloc::vec::Vec<u8>
    {
        let total = NDP_HDR_FIXED + 8;
        let mut buf = alloc::vec![0u8; total];
        buf[0] = NDP_NA;
        buf[1] = 0;
        buf[2] = 0; buf[3] = 0;
        // Flags: bit 0x80000000 (R, router) | 0x40000000 (S, solicited) |
        //        0x20000000 (O, override). Default: S=1.
        let flags = flags_so | 0x4000_0000;
        buf[4..8].copy_from_slice(&flags.to_be_bytes());
        buf[8..24].copy_from_slice(&target_ip.0);
        buf[24] = NDP_OPT_TARGET_LLADDR;
        buf[25] = 1;
        buf[26..32].copy_from_slice(&our_mac.0);
        let cs = compute_ndp_checksum(&buf, src, dst);
        buf[2..4].copy_from_slice(&cs.to_be_bytes());
        buf
    }

    /// Parse an NS/NA. Validates checksum + decodes the optional
    /// lladdr (T=1 SOURCE on NS, T=2 TARGET on NA).
    /// # C: O(N)
    pub fn parse(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<Self, NdpError> {
        if buf.len() < NDP_HDR_FIXED { return Err(NdpError::Short); }
        if buf[0] != NDP_NS && buf[0] != NDP_NA { return Err(NdpError::BadType); }
        if compute_ndp_checksum_with_field(buf, src, dst, true) != 0 {
            return Err(NdpError::BadChecksum);
        }
        let typ = buf[0];
        let flags = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut t = [0u8; 16]; t.copy_from_slice(&buf[8..24]);
        let target = Ipv6Addr(t);
        // Walk options.
        let mut o = NDP_HDR_FIXED;
        let mut lladdr = None;
        while o + 2 <= buf.len() {
            let opt_type = buf[o];
            let opt_len  = buf[o + 1] as usize * 8;
            if opt_len < 8 || o + opt_len > buf.len() { break; }
            if (opt_type == NDP_OPT_SOURCE_LLADDR && typ == NDP_NS)
                || (opt_type == NDP_OPT_TARGET_LLADDR && typ == NDP_NA)
            {
                if opt_len >= 8 {
                    let mut m = [0u8; 6]; m.copy_from_slice(&buf[o+2..o+8]);
                    lladdr = Some(MacAddr(m));
                }
            }
            o += opt_len;
        }
        Ok(Self { typ, flags, target, lladdr })
    }
}

impl RouterAdvertisement {
    /// Parse an ICMPv6 Router Advertisement and Prefix Information options.
    /// # C: O(N options)
    pub fn parse(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Result<Self, NdpError> {
        if buf.len() < NDP_RA_FIXED { return Err(NdpError::Short); }
        if buf[0] != NDP_RA { return Err(NdpError::BadType); }
        if compute_ndp_checksum_with_field(buf, src, dst, true) != 0 {
            return Err(NdpError::BadChecksum);
        }
        let mut ra = Self {
            hop_limit: buf[4],
            flags: buf[5],
            router_lifetime: u16::from_be_bytes([buf[6], buf[7]]),
            reachable_time: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            retrans_timer: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            source_lladdr: None,
            prefixes: alloc::vec::Vec::new(),
        };
        let mut off = NDP_RA_FIXED;
        while off + 2 <= buf.len() {
            let opt_type = buf[off];
            let opt_len = buf[off + 1] as usize * 8;
            if opt_len < 8 || off + opt_len > buf.len() { break; }
            let opt = &buf[off..off + opt_len];
            match opt_type {
                NDP_OPT_SOURCE_LLADDR if opt_len >= 8 => {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&opt[2..8]);
                    ra.source_lladdr = Some(MacAddr(mac));
                }
                NDP_OPT_PREFIX_INFO if opt_len >= 32 => {
                    let mut prefix = [0u8; 16];
                    prefix.copy_from_slice(&opt[16..32]);
                    ra.prefixes.push(PrefixInfo {
                        prefix_len: opt[2],
                        flags: opt[3],
                        valid_lifetime: u32::from_be_bytes([opt[4], opt[5], opt[6], opt[7]]),
                        preferred_lifetime: u32::from_be_bytes([opt[8], opt[9], opt[10], opt[11]]),
                        prefix: Ipv6Addr(prefix),
                    });
                }
                _ => {}
            }
            off += opt_len;
        }
        Ok(ra)
    }

    /// Test/support builder for one-prefix RAs. # C: O(1)
    pub fn build_one_prefix(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        mac: MacAddr,
        router_lifetime: u16,
        prefix: Ipv6Addr,
        prefix_len: u8,
        flags: u8,
    ) -> alloc::vec::Vec<u8> {
        let total = NDP_RA_FIXED + 8 + 32;
        let mut buf = alloc::vec![0u8; total];
        buf[0] = NDP_RA;
        buf[1] = 0;
        buf[4] = 64;
        buf[6..8].copy_from_slice(&router_lifetime.to_be_bytes());
        buf[16] = NDP_OPT_SOURCE_LLADDR;
        buf[17] = 1;
        buf[18..24].copy_from_slice(&mac.0);
        let p = 24;
        buf[p] = NDP_OPT_PREFIX_INFO;
        buf[p + 1] = 4;
        buf[p + 2] = prefix_len;
        buf[p + 3] = flags;
        buf[p + 4..p + 8].copy_from_slice(&3600u32.to_be_bytes());
        buf[p + 8..p + 12].copy_from_slice(&1800u32.to_be_bytes());
        buf[p + 16..p + 32].copy_from_slice(&prefix.0);
        let cs = compute_ndp_checksum(&buf, src, dst);
        buf[2..4].copy_from_slice(&cs.to_be_bytes());
        buf
    }
}

fn compute_ndp_checksum(buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> u16 {
    compute_ndp_checksum_with_field(buf, src, dst, false)
}

fn compute_ndp_checksum_with_field(
    buf: &[u8], src: Ipv6Addr, dst: Ipv6Addr, include_field: bool,
) -> u16 {
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&src.0);
    pseudo[16..32].copy_from_slice(&dst.0);
    pseudo[32..36].copy_from_slice(&(buf.len() as u32).to_be_bytes());
    pseudo[39] = IPPROTO_ICMPV6;
    let mut all = alloc::vec::Vec::with_capacity(40 + buf.len());
    all.extend_from_slice(&pseudo);
    all.extend_from_slice(buf);
    if !include_field && all.len() >= 40 + 4 {
        all[40 + 2] = 0;
        all[40 + 3] = 0;
    }
    ip_checksum(&all)
}

/// Per-iface IPv6 neighbor cache (mirrors ArpCache).
pub struct NdpCache {
    pub(crate) inner: Spinlock<BTreeMap<Ipv6Addr, MacAddr>, NdpLockClass>,
}

impl NdpCache {
    /// # C: O(1)
    pub const fn new() -> Self { Self { inner: Spinlock::new(BTreeMap::new()) } }
    /// # C: O(1)
    pub fn insert(&self, ip: Ipv6Addr, mac: MacAddr) { self.inner.lock().insert(ip, mac); }
    /// # C: O(N)
    pub fn lookup(&self, ip: Ipv6Addr) -> Option<MacAddr> {
        self.inner.lock().get(&ip).copied()
    }
}

impl Default for NdpCache { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ns_round_trip() {
        let src = Ipv6Addr::LOOPBACK;
        let dst = Ipv6Addr::LOOPBACK;
        let mac = MacAddr([1,2,3,4,5,6]);
        let target = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,1]);
        let buf = NdpMsg::build_ns(src, dst, mac, target);
        let p = NdpMsg::parse(&buf, src, dst).unwrap();
        assert_eq!(p.typ, NDP_NS);
        assert_eq!(p.target, target);
        assert_eq!(p.lladdr, Some(mac));
    }

    #[test]
    fn na_round_trip() {
        let src = Ipv6Addr::LOOPBACK;
        let dst = Ipv6Addr::LOOPBACK;
        let mac = MacAddr([0xa,0xb,0xc,0xd,0xe,0xf]);
        let target = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,2]);
        let buf = NdpMsg::build_na(src, dst, mac, target, 0x2000_0000);
        let p = NdpMsg::parse(&buf, src, dst).unwrap();
        assert_eq!(p.typ, NDP_NA);
        assert!((p.flags & 0x4000_0000) != 0, "S bit set");
        assert!((p.flags & 0x2000_0000) != 0, "O bit propagated");
        assert_eq!(p.lladdr, Some(mac));
    }

    #[test]
    fn rejects_bad_checksum() {
        let src = Ipv6Addr::LOOPBACK;
        let mut buf = NdpMsg::build_ns(src, src, MacAddr::ZERO, src);
        buf[10] ^= 0xFF;
        assert_eq!(NdpMsg::parse(&buf, src, src).err().unwrap(), NdpError::BadChecksum);
    }

    #[test]
    fn cache_lookup() {
        let c = NdpCache::new();
        c.insert(Ipv6Addr::LOOPBACK, MacAddr([1,1,1,1,1,1]));
        assert_eq!(c.lookup(Ipv6Addr::LOOPBACK), Some(MacAddr([1,1,1,1,1,1])));
    }

    #[test]
    fn ra_prefix_round_trip() {
        let src = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
        let dst = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,1]);
        let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x55,0,0,0,0,0]);
        let mac = MacAddr([2,3,4,5,6,7]);
        let buf = RouterAdvertisement::build_one_prefix(
            src, dst, mac, 1800, prefix, 64, NDP_PIO_FLAG_ONLINK | NDP_PIO_FLAG_AUTO,
        );
        let ra = RouterAdvertisement::parse(&buf, src, dst).unwrap();
        assert_eq!(ra.router_lifetime, 1800);
        assert_eq!(ra.source_lladdr, Some(mac));
        assert_eq!(ra.prefixes.len(), 1);
        assert_eq!(ra.prefixes[0].prefix, prefix);
        assert_eq!(ra.prefixes[0].prefix_len, 64);
    }
}
