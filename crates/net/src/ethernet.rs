// Ethernet II frame header — 14 bytes: dst[6] + src[6] + ethertype[2].
// Per IEEE 802.3 / `25§4` link layer. The optional 802.1Q VLAN
// tag (4 extra bytes) is parsed when ethertype == 0x8100; v1
// strips it transparently and surfaces the inner ethertype.

use crate::addr::{eth_p, MacAddr};

pub const ETH_HDR_LEN: usize = 14;
pub const ETH_VLAN_TAG_LEN: usize = 4;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EthError { Short }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EthHdr {
    pub dst:        MacAddr,
    pub src:        MacAddr,
    pub ethertype:  u16,
    /// VLAN tag if the frame was 0x8100-tagged. None for untagged.
    pub vlan_tag:   Option<u16>,
    /// Byte offset to the L3 payload (14 untagged, 18 tagged).
    pub hdr_len:    usize,
}

impl EthHdr {
    /// # C: O(N)
    pub fn parse(buf: &[u8]) -> Result<Self, EthError> {
        if buf.len() < ETH_HDR_LEN { return Err(EthError::Short); }
        let mut dst = [0u8; 6]; dst.copy_from_slice(&buf[0..6]);
        let mut src = [0u8; 6]; src.copy_from_slice(&buf[6..12]);
        let outer_et = u16::from_be_bytes([buf[12], buf[13]]);
        if outer_et == eth_p::VLAN {
            if buf.len() < ETH_HDR_LEN + ETH_VLAN_TAG_LEN { return Err(EthError::Short); }
            let tag = u16::from_be_bytes([buf[14], buf[15]]);
            let inner_et = u16::from_be_bytes([buf[16], buf[17]]);
            return Ok(Self {
                dst: MacAddr(dst), src: MacAddr(src),
                ethertype: inner_et, vlan_tag: Some(tag),
                hdr_len: ETH_HDR_LEN + ETH_VLAN_TAG_LEN,
            });
        }
        Ok(Self {
            dst: MacAddr(dst), src: MacAddr(src),
            ethertype: outer_et, vlan_tag: None,
            hdr_len: ETH_HDR_LEN,
        })
    }

    /// Write a 14-byte untagged header into the start of `buf`.
    /// Caller writes the L3 payload after byte 14.
    /// # C: O(1)
    pub fn write_to(dst: MacAddr, src: MacAddr, ethertype: u16, buf: &mut [u8]) {
        buf[0..6].copy_from_slice(&dst.0);
        buf[6..12].copy_from_slice(&src.0);
        buf[12..14].copy_from_slice(&ethertype.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_untagged() {
        let mut buf = [0u8; ETH_HDR_LEN + 8];
        EthHdr::write_to(
            MacAddr([1,2,3,4,5,6]), MacAddr([0xa,0xb,0xc,0xd,0xe,0xf]),
            eth_p::IPV4, &mut buf,
        );
        let h = EthHdr::parse(&buf).unwrap();
        assert_eq!(h.dst, MacAddr([1,2,3,4,5,6]));
        assert_eq!(h.ethertype, eth_p::IPV4);
        assert!(h.vlan_tag.is_none());
        assert_eq!(h.hdr_len, ETH_HDR_LEN);
    }

    #[test]
    fn parse_tagged() {
        // dst, src, 0x8100, tag=0x1234, inner=0x0800
        let mut buf = [0u8; ETH_HDR_LEN + ETH_VLAN_TAG_LEN + 4];
        buf[0..6].copy_from_slice(&[0xff; 6]);
        buf[6..12].copy_from_slice(&[1,2,3,4,5,6]);
        buf[12..14].copy_from_slice(&eth_p::VLAN.to_be_bytes());
        buf[14..16].copy_from_slice(&0x1234u16.to_be_bytes());
        buf[16..18].copy_from_slice(&eth_p::IPV4.to_be_bytes());
        let h = EthHdr::parse(&buf).unwrap();
        assert_eq!(h.vlan_tag, Some(0x1234));
        assert_eq!(h.ethertype, eth_p::IPV4);
        assert_eq!(h.hdr_len, 18);
    }

    #[test]
    fn rejects_short() {
        let buf = [0u8; 8];
        assert_eq!(EthHdr::parse(&buf).err().unwrap(), EthError::Short);
    }
}
