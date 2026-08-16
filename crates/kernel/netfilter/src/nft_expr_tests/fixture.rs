//! Synthetic packets and subsystem stand-ins the expression tests drive.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use conntrack::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};

use crate::nft_expr::access::*;
use crate::nft_expr::limits::IFNAMSIZ;

/// IPv4 header with a chosen protocol, source, destination and TTL.
/// # C: O(len)
pub fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

/// TCP header bytes with a chosen control field and option area. # C: O(len)
pub fn tcp(sport: u16, dport: u16, control: u8, options: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    let hdr_words = (20 + options.len()) / 4;
    t[12] = (hdr_words as u8) << 4;
    t[13] = control;
    t.extend_from_slice(options);
    while t.len() % 4 != 0 { t.push(0); }
    t
}

/// UDP header bytes. # C: O(1)
pub fn udp(sport: u16, dport: u16) -> Vec<u8> {
    let mut u = vec![0u8; 8];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u
}

/// Conntrack stand-in whose every answer the test names. Nothing is derived,
/// so a wrong read shows up as the value the test did not set.
pub struct Ct {
    pub ctinfo: u8,
    pub attached: bool,
    pub template: bool,
    pub status: u32,
    pub mark: core::cell::Cell<u32>,
    pub secmark: core::cell::Cell<u32>,
    pub events: core::cell::Cell<u32>,
    pub expiration_ms: u32,
    pub helper: Option<[u8; IFNAMSIZ]>,
    pub counters: [(u64, u64); 2],
    pub tuples: [Option<Tuple>; 2],
    pub zone: u16,
    pub id: u32,
    pub offloadable: bool,
    pub connlimit: Option<u32>,
}

impl Default for Ct {
    fn default() -> Self {
        Self {
            ctinfo: conntrack::uapi::IP_CT_NEW, attached: true, template: false, status: 0,
            mark: core::cell::Cell::new(0), secmark: core::cell::Cell::new(0),
            events: core::cell::Cell::new(0), expiration_ms: 0, helper: None,
            counters: [(0, 0); 2], tuples: [None, None], zone: 0, id: 0,
            offloadable: false, connlimit: None,
        }
    }
}

impl CtAccess for Ct {
    fn ctinfo(&self) -> u8 { self.ctinfo }
    fn attached(&self) -> bool { self.attached }
    fn template(&self) -> bool { self.template }
    fn status(&self) -> u32 { self.status }
    fn mark(&self) -> u32 { self.mark.get() }
    fn set_mark(&self, value: u32) { self.mark.set(value); }
    fn secmark(&self) -> u32 { self.secmark.get() }
    fn set_secmark(&self, value: u32) { self.secmark.set(value); }
    fn expiration_ms(&self) -> u32 { self.expiration_ms }
    fn helper(&self, out: &mut [u8]) -> bool {
        match self.helper { Some(name) => { out.copy_from_slice(&name); true } None => false }
    }
    fn eventmask(&self) -> u32 { self.events.get() }
    fn set_eventmask(&self, value: u32) { self.events.set(self.events.get() | value); }
    fn counters(&self, dir: u8) -> (u64, u64) { self.counters[dir as usize] }
    fn tuple(&self, dir: u8) -> Option<Tuple> { self.tuples[dir as usize] }
    fn zone(&self) -> u16 { self.zone }
    fn id(&self) -> u32 { self.id }
    fn offloadable(&self) -> bool { self.offloadable }
    fn connlimit_count(&self, _index: usize) -> Option<u32> { self.connlimit }
}

/// One IPv4 TCP tuple. # C: O(1)
pub fn tuple4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Tuple {
    Tuple {
        src: TupleEnd { addr: InetAddr::v4(src), proto: ProtoPart::port(sport) },
        dst: TupleEnd { addr: InetAddr::v4(dst), proto: ProtoPart::port(dport) },
        l3num: conntrack::uapi::NFPROTO_IPV4,
        protonum: conntrack::uapi::IPPROTO_TCP,
        zone: 0,
    }
}

/// Route stand-in.
#[derive(Default)]
pub struct Route {
    pub classid: Option<u32>,
    pub nexthop4: Option<[u8; 4]>,
    pub nexthop6: Option<[u8; 16]>,
    pub tcpmss: Option<u16>,
    pub transformed: bool,
    pub src_addr: Option<InetAddr>,
    pub iface_addr: Option<InetAddr>,
    pub fib: Option<FibEntry>,
}

impl RouteAccess for Route {
    fn classid(&self) -> Option<u32> { self.classid }
    fn nexthop4(&self) -> Option<[u8; 4]> { self.nexthop4 }
    fn nexthop6(&self) -> Option<[u8; 16]> { self.nexthop6 }
    fn tcpmss(&self) -> Option<u16> { self.tcpmss }
    fn transformed(&self) -> bool { self.transformed }
    fn src_addr(&self) -> Option<InetAddr> { self.src_addr }
    fn iface_addr(&self) -> Option<InetAddr> { self.iface_addr }
    fn fib(&self, _key: &FibKey) -> Option<FibEntry> { self.fib }
}

/// Socket stand-in.
#[derive(Default)]
pub struct Sock {
    pub present: bool,
    pub full: bool,
    pub transparent: bool,
    pub mark: u32,
    pub wildcard: bool,
    pub cgroup: Option<u64>,
    pub tproxy_ok: bool,
}

impl SocketAccess for Sock {
    fn present(&self) -> bool { self.present }
    fn full(&self) -> bool { self.full }
    fn transparent(&self) -> bool { self.transparent }
    fn mark(&self) -> u32 { self.mark }
    fn wildcard(&self) -> bool { self.wildcard }
    fn cgroup_id(&self, _level: u32) -> Option<u64> { self.cgroup }
    fn tproxy_transparent(&self, _addr: &InetAddr, _port: u16) -> bool { self.tproxy_ok }
}

/// Transform-state stand-in.
#[derive(Default)]
pub struct Xfrm { pub state: Option<XfrmState> }

impl XfrmAccess for Xfrm {
    fn state(&self, _dir: u32, _spnum: u32) -> Option<XfrmState> { self.state }
}

/// Tunnel-metadata stand-in.
#[derive(Default)]
pub struct Tunnel { pub mode: u32, pub id: Option<u32> }

impl TunnelAccess for Tunnel {
    fn present(&self, mode: u32) -> bool { mode == self.mode }
    fn id(&self, mode: u32) -> Option<u32> { if mode == self.mode { self.id } else { None } }
}

/// Fingerprint stand-in.
pub struct Osf { pub genre: &'static [u8] }

impl OsfAccess for Osf {
    fn genre(&self, _ttl: u8, _with_version: bool, out: &mut [u8]) -> bool {
        out[..self.genre.len()].copy_from_slice(self.genre);
        true
    }
}

/// Handshake-cookie stand-in.
pub struct Cookies { pub valid: bool }

impl SynproxyAccess for Cookies {
    fn cookie_valid(&self, _seq: u32, _ack: u32) -> Option<u16> { self.valid.then_some(0) }
}
