// ARP — RFC 826 Address Resolution Protocol for IPv4 over
// Ethernet. 28-byte payload sitting under an Ethernet header
// (ETH_P_ARP=0x0806). Two opcodes that matter: REQUEST (1) and
// REPLY (2). The neighbor cache lives next to the registry —
// `ArpCache` keeps a small `BTreeMap<Ipv4Addr, MacAddr>`.

extern crate alloc;
use alloc::collections::BTreeMap;

use sync::{Spinlock, Socket as ArpLockClass};

use crate::addr::{Ipv4Addr, MacAddr};

pub const ARP_HW_ETHER: u16 = 1;
pub const ARP_PROTO_IPV4: u16 = 0x0800;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY:   u16 = 2;
pub const ARP_LEN: usize = 28;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArpError { Short, BadHwType, BadProto, BadOp }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ArpPkt {
    pub opcode:   u16,
    pub sender_mac: MacAddr,
    pub sender_ip:  Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip:  Ipv4Addr,
}

impl ArpPkt {
    /// # C: O(N)
    pub fn parse(buf: &[u8]) -> Result<Self, ArpError> {
        if buf.len() < ARP_LEN { return Err(ArpError::Short); }
        let hw    = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        let _hlen = buf[4];
        let _plen = buf[5];
        let op    = u16::from_be_bytes([buf[6], buf[7]]);
        if hw != ARP_HW_ETHER { return Err(ArpError::BadHwType); }
        if proto != ARP_PROTO_IPV4 { return Err(ArpError::BadProto); }
        if op != ARP_OP_REQUEST && op != ARP_OP_REPLY { return Err(ArpError::BadOp); }
        let mut sm = [0u8; 6]; sm.copy_from_slice(&buf[ 8..14]);
        let si = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);
        let mut tm = [0u8; 6]; tm.copy_from_slice(&buf[18..24]);
        let ti = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        Ok(Self {
            opcode: op,
            sender_mac: MacAddr(sm), sender_ip: Ipv4Addr::from_u32(si),
            target_mac: MacAddr(tm), target_ip: Ipv4Addr::from_u32(ti),
        })
    }

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&ARP_HW_ETHER.to_be_bytes());
        buf[2..4].copy_from_slice(&ARP_PROTO_IPV4.to_be_bytes());
        buf[4] = 6;  // hw addr len
        buf[5] = 4;  // proto addr len
        buf[6..8].copy_from_slice(&self.opcode.to_be_bytes());
        buf[ 8..14].copy_from_slice(&self.sender_mac.0);
        buf[14..18].copy_from_slice(&self.sender_ip.octets());
        buf[18..24].copy_from_slice(&self.target_mac.0);
        buf[24..28].copy_from_slice(&self.target_ip.octets());
    }
}

/// Build a REQUEST asking who has `target_ip`. Caller wraps in
/// an Ethernet frame with dst=BROADCAST + ETH_P_ARP.
/// # C: O(1)
pub fn build_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr)
    -> alloc::vec::Vec<u8>
{
    let mut buf = alloc::vec![0u8; ARP_LEN];
    let p = ArpPkt {
        opcode: ARP_OP_REQUEST,
        sender_mac, sender_ip,
        target_mac: MacAddr::ZERO,
        target_ip,
    };
    p.write_to(&mut buf);
    buf
}

/// Build a REPLY for a received REQUEST.
/// # C: O(1)
pub fn build_reply(req: &ArpPkt, our_mac: MacAddr) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec![0u8; ARP_LEN];
    let p = ArpPkt {
        opcode: ARP_OP_REPLY,
        sender_mac: our_mac, sender_ip: req.target_ip,
        target_mac: req.sender_mac, target_ip: req.sender_ip,
    };
    p.write_to(&mut buf);
    buf
}

/// Per-iface ARP neighbor cache.
pub struct ArpCache {
    pub(crate) inner: Spinlock<BTreeMap<Ipv4Addr, MacAddr>, ArpLockClass>,
}

impl ArpCache {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(BTreeMap::new()) }
    }

    /// # C: O(1)
    pub fn insert(&self, ip: Ipv4Addr, mac: MacAddr) {
        self.inner.lock().insert(ip, mac);
    }

    /// # C: O(N)
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.inner.lock().get(&ip).copied()
    }

    /// # C: O(1)
    pub fn snapshot(&self) -> alloc::vec::Vec<(Ipv4Addr, MacAddr)> {
        self.inner.lock().iter().map(|(k, v)| (*k, *v)).collect()
    }
}

impl Default for ArpCache { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = ArpPkt {
            opcode: ARP_OP_REQUEST,
            sender_mac: MacAddr([1,2,3,4,5,6]),
            sender_ip:  Ipv4Addr::new(10, 0, 0, 1),
            target_mac: MacAddr::ZERO,
            target_ip:  Ipv4Addr::new(10, 0, 0, 2),
        };
        let mut buf = alloc::vec![0u8; ARP_LEN];
        p.write_to(&mut buf);
        let q = ArpPkt::parse(&buf).unwrap();
        assert_eq!(q, p);
    }

    #[test]
    fn build_reply_from_request() {
        let req = ArpPkt {
            opcode: ARP_OP_REQUEST,
            sender_mac: MacAddr([1,2,3,4,5,6]),
            sender_ip:  Ipv4Addr::new(10, 0, 0, 1),
            target_mac: MacAddr::ZERO,
            target_ip:  Ipv4Addr::new(10, 0, 0, 2),
        };
        let our_mac = MacAddr([0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0]);
        let reply = build_reply(&req, our_mac);
        let p = ArpPkt::parse(&reply).unwrap();
        assert_eq!(p.opcode, ARP_OP_REPLY);
        assert_eq!(p.sender_mac, our_mac);
        assert_eq!(p.sender_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(p.target_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn cache_round_trip() {
        let c = ArpCache::new();
        c.insert(Ipv4Addr::new(192, 168, 1, 5), MacAddr([5,6,7,8,9,10]));
        assert_eq!(c.lookup(Ipv4Addr::new(192, 168, 1, 5)),
                   Some(MacAddr([5,6,7,8,9,10])));
        assert_eq!(c.lookup(Ipv4Addr::new(1,2,3,4)), None);
    }

    #[test]
    fn rejects_short() {
        let buf = [0u8; 16];
        assert_eq!(ArpPkt::parse(&buf).err().unwrap(), ArpError::Short);
    }
}
