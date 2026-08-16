// Conversion between the two frame formats: what the network stack above
// hands down, and what goes on the air.
//
// The address mapping is the part that has four cases and no default. Which
// header field holds the destination depends on the two distribution-system
// bits, and a conversion that assumed one layout produces frames addressed to
// the wrong station in three of the four. The layouts are also checked
// against the interface type: a frame travelling toward the distribution
// system arriving on a client interface is not a frame with an unusual
// address map, it is a frame that does not belong here.

extern crate alloc;

use alloc::vec::Vec;

use wireless::ieee80211::{build, fctl, hdr::MacHeader, MacAddr};
use wireless::uapi::enums::IfType;

use crate::uapi::{ETH_HDR_LEN, ETH_P_802_3_MIN, ETH_P_AARP, ETH_P_IPX, SNAP_HDR_LEN};

/// One converted Ethernet frame: the two addresses, the protocol field, and
/// the payload with no link header in front of it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthFrame {
    pub dst: MacAddr,
    pub src: MacAddr,
    /// EtherType, or the payload length when the frame carried no recognised
    /// encapsulation.
    pub proto: u16,
    pub payload: Vec<u8>,
}

impl EthFrame {
    /// The whole frame with its Ethernet header, as the stack above expects
    /// it. # C: O(len)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ETH_HDR_LEN + self.payload.len());
        out.extend_from_slice(&self.dst.0);
        out.extend_from_slice(&self.src.0);
        out.extend_from_slice(&self.proto.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
    /// Read an Ethernet frame off the wire format. # C: O(len)
    pub fn parse(frame: &[u8]) -> Option<Self> {
        if frame.len() < ETH_HDR_LEN { return None; }
        Some(Self {
            dst: MacAddr::from_slice(&frame[0..6])?,
            src: MacAddr::from_slice(&frame[6..12])?,
            proto: u16::from_be_bytes([frame[12], frame[13]]),
            payload: frame[ETH_HDR_LEN..].to_vec(),
        })
    }
}

/// Whether an interface type may receive a frame with this pair of
/// distribution-system bits. This is a membership check, not a formatting
/// one: a client that accepted a frame travelling toward the distribution
/// system would forward traffic addressed to its access point. # C: O(1)
pub fn ds_bits_allowed(iftype: IfType, tods: bool, fromds: bool) -> bool {
    match (tods, fromds) {
        // Toward the distribution system: only something that IS one.
        (true, false) => matches!(iftype, IfType::Ap | IfType::ApVlan | IfType::P2pGo),
        // Both: a bridged link between two distribution systems.
        (true, true) => matches!(iftype, IfType::MeshPoint | IfType::ApVlan | IfType::Station),
        // From the distribution system: a client of one.
        (false, true) => matches!(iftype,
            IfType::Station | IfType::P2pClient | IfType::MeshPoint),
        // Neither: a direct exchange between two stations.
        (false, false) => matches!(iftype,
            IfType::Adhoc | IfType::Station | IfType::Ocb | IfType::NanData),
    }
}

/// Whether a payload begins with an encapsulation whose EtherType may be
/// lifted out. The two protocols the RFC 1042 form cannot carry must arrive
/// under the bridge-tunnel form, and a frame that carries them under RFC 1042
/// is NOT unwrapped — lifting the type out of it would silently accept a
/// frame built the way the standard forbids. # C: O(1)
pub fn tunnel_proto(payload: &[u8]) -> Option<u16> {
    if payload.len() < SNAP_HDR_LEN { return None; }
    let snap = &payload[..6];
    let proto = u16::from_be_bytes([payload[6], payload[7]]);
    let rfc1042_ok = snap == build::RFC1042_HEADER
        && proto != ETH_P_AARP && proto != ETH_P_IPX;
    let bridge_ok = snap == build::BRIDGE_TUNNEL_HEADER;
    if rfc1042_ok || bridge_ok { Some(proto) } else { None }
}

/// Convert a received data frame into an Ethernet frame. `own_addr` is the
/// interface's own address, needed for the rule that a client must not accept
/// a multicast frame it apparently sent itself — which is what a frame looped
/// back by an access point looks like. # C: O(len)
pub fn to_8023(header: &MacHeader, body: &[u8], iftype: IfType, own_addr: MacAddr)
    -> Option<EthFrame>
{
    let fc = header.frame_control;
    if !fctl::is_data(fc) || fctl::is_nodata(fc) { return None; }
    let tods = fc & fctl::FCTL_TODS != 0;
    let fromds = fc & fctl::FCTL_FROMDS != 0;
    if !ds_bits_allowed(iftype, tods, fromds) { return None; }

    let dst = header.destination()?;
    let src = header.source()?;
    if !tods && fromds && dst.is_multicast() && src == own_addr { return None; }

    match tunnel_proto(body) {
        Some(proto) => Some(EthFrame { dst, src, proto, payload: body[SNAP_HDR_LEN..].to_vec() }),
        // No recognised encapsulation: the two-byte field carries the payload
        // length, which is what an 802.3 frame means by it.
        None => Some(EthFrame { dst, src, proto: body.len() as u16, payload: body.to_vec() }),
    }
}

/// Build an 802.11 data frame from an Ethernet one. `bssid` is the network
/// the interface belongs to; the interface type decides which of the two
/// three-address layouts is used. Returns the whole frame with a zero
/// sequence-control field — the transmit path fills that in, because only it
/// knows the counter. # C: O(len)
pub fn from_8023(eth: &EthFrame, iftype: IfType, own_addr: MacAddr, bssid: MacAddr,
                 tid: Option<u8>, protected: bool) -> Option<Vec<u8>>
{
    let mut out = Vec::with_capacity(36 + SNAP_HDR_LEN + eth.payload.len());
    match iftype {
        IfType::Station | IfType::P2pClient =>
            build::data_header_to_ds(&mut out, bssid, own_addr, eth.dst, tid, protected),
        IfType::Ap | IfType::ApVlan | IfType::P2pGo =>
            build::data_header_from_ds(&mut out, eth.dst, bssid, eth.src, tid, protected),
        IfType::Adhoc | IfType::Ocb => {
            let mut fc = fctl::FTYPE_DATA;
            if tid.is_some() { fc |= fctl::data_stype::QOS; }
            if protected { fc |= fctl::FCTL_PROTECTED; }
            out.extend_from_slice(&fc.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&eth.dst.0);
            out.extend_from_slice(&own_addr.0);
            out.extend_from_slice(&bssid.0);
            out.extend_from_slice(&0u16.to_le_bytes());
            if let Some(t) = tid {
                out.extend_from_slice(&((t as u16) & fctl::QOS_CTL_TID_MASK).to_le_bytes());
            }
        }
        _ => return None,
    }
    // A frame whose protocol field is really a length carries no
    // encapsulation, so none is added back.
    if eth.proto >= ETH_P_802_3_MIN { build::snap_header(&mut out, eth.proto); }
    out.extend_from_slice(&eth.payload);
    Some(out)
}

/// Alignment every aggregated subframe but the last is padded to.
pub const AMSDU_PAD: usize = 4;

/// Split an aggregated MSDU into its subframes. A subframe whose length field
/// runs past the end of the buffer aborts the whole walk: continuing would
/// read the next subframe's header out of the middle of this one's payload.
/// # C: O(len)
pub fn parse_amsdu(body: &[u8]) -> Option<Vec<EthFrame>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + ETH_HDR_LEN <= body.len() {
        let dst = MacAddr::from_slice(&body[at..])?;
        let src = MacAddr::from_slice(&body[at + 6..])?;
        let len = u16::from_be_bytes([body[at + 12], body[at + 13]]) as usize;
        let start = at + ETH_HDR_LEN;
        let end = start.checked_add(len)?;
        if end > body.len() { return None; }
        let sub = &body[start..end];
        let (proto, payload) = match tunnel_proto(sub) {
            Some(p) => (p, sub[SNAP_HDR_LEN..].to_vec()),
            None => (len as u16, sub.to_vec()),
        };
        out.push(EthFrame { dst, src, proto, payload });
        at = end + (AMSDU_PAD - end % AMSDU_PAD) % AMSDU_PAD;
        // The last subframe carries no padding, so a walk that lands exactly
        // on the end is complete rather than truncated.
        if at >= body.len() { break; }
    }
    if out.is_empty() { None } else { Some(out) }
}
