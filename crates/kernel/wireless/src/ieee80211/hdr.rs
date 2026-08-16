// The 802.11 MAC header: its width, its addressing, and what the DS bits do
// to the meaning of each address field.

use super::fctl;

/// Width of an 802.11 address.
pub const ADDR_LEN: usize = 6;
/// Shortest header any frame type has — an ACK or CTS.
pub const MIN_MAC_HDR_LEN: usize = 10;
/// Widest header: four addresses, QoS control and HT control.
pub const MAX_MAC_HDR_LEN: usize = 36;
/// Width of a three-address header before any optional field.
pub const HDR_LEN_3ADDR: usize = 24;
/// Width of a four-address header before any optional field.
pub const HDR_LEN_4ADDR: usize = 30;

/// One 802.11 station address.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MacAddr(pub [u8; ADDR_LEN]);

impl MacAddr {
    /// All-ones — the broadcast destination.
    pub const BROADCAST: Self = Self([0xff; ADDR_LEN]);
    /// All-zero — the wildcard a scan sends and never a real station.
    pub const ZERO: Self = Self([0; ADDR_LEN]);

    /// Read an address out of the front of a slice. # C: O(1)
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        let mut out = [0u8; ADDR_LEN];
        out.copy_from_slice(b.get(..ADDR_LEN)?);
        Some(Self(out))
    }
    /// Raw bytes in transmission order. # C: O(1)
    pub fn as_bytes(&self) -> &[u8; ADDR_LEN] { &self.0 }
    /// Group bit set — the frame is for more than one receiver. # C: O(1)
    pub fn is_multicast(&self) -> bool { self.0[0] & 0x01 != 0 }
    /// Every byte all-ones. # C: O(1)
    pub fn is_broadcast(&self) -> bool { self.0 == Self::BROADCAST.0 }
    /// Every byte zero. # C: O(1)
    pub fn is_zero(&self) -> bool { self.0 == Self::ZERO.0 }
    /// Addressable as a single station: not the wildcard, not a group.
    /// # C: O(1)
    pub fn is_unicast(&self) -> bool { !self.is_multicast() && !self.is_zero() }
    /// Locally administered bit set. # C: O(1)
    pub fn is_local(&self) -> bool { self.0[0] & 0x02 != 0 }
}

/// Header width implied by a frame-control word, matching the standard's
/// per-type layout: an extension frame has a 4-byte header, a control frame
/// 10 bytes for ACK and CTS and 16 for the rest, a data frame grows for the
/// fourth address, the QoS-control field and the HT-control field, and a
/// management frame grows only for HT control. # C: O(1)
pub fn hdrlen(fc: u16) -> usize {
    if fctl::ftype(fc) == fctl::FTYPE_EXT { return 4; }
    if fctl::is_data(fc) {
        let mut len = if fctl::has_a4(fc) { HDR_LEN_4ADDR } else { HDR_LEN_3ADDR };
        if fctl::is_data_qos(fc) {
            len += fctl::QOS_CTL_LEN;
            if fc & fctl::FCTL_ORDER != 0 { len += fctl::HT_CTL_LEN; }
        }
        return len;
    }
    if fctl::is_mgmt(fc) {
        return HDR_LEN_3ADDR + if fc & fctl::FCTL_ORDER != 0 { fctl::HT_CTL_LEN } else { 0 };
    }
    if fctl::is_ctl(fc) {
        // ACK and CTS share the three subtype bits that select the short form.
        return if fc & 0x00e0 == 0x00c0 { 10 } else { 16 };
    }
    HDR_LEN_3ADDR
}

/// A parsed MAC header. Addresses beyond what the frame carries are `None`
/// rather than zeroed, so a caller cannot mistake an absent address for the
/// wildcard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacHeader {
    pub frame_control: u16,
    pub duration_id: u16,
    pub addr1: MacAddr,
    pub addr2: Option<MacAddr>,
    pub addr3: Option<MacAddr>,
    pub seq_ctrl: Option<u16>,
    pub addr4: Option<MacAddr>,
    pub qos_ctrl: Option<u16>,
    /// Header width in bytes — where the frame body starts.
    pub len: usize,
}

impl MacHeader {
    /// Parse a header off the front of a received frame. A frame shorter than
    /// the width its own frame-control word implies is rejected here, before
    /// any field past the truncation is read. # C: O(1)
    pub fn parse(frame: &[u8]) -> Option<Self> {
        if frame.len() < 4 { return None; }
        let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
        let duration_id = u16::from_le_bytes([frame[2], frame[3]]);
        let len = hdrlen(frame_control);
        if frame.len() < len { return None; }
        if len < 10 {
            // An extension frame has no addressing this parser can describe.
            return None;
        }
        let addr1 = MacAddr::from_slice(&frame[4..])?;
        let addr2 = if len >= 16 { MacAddr::from_slice(&frame[10..]) } else { None };
        let addr3 = if len >= HDR_LEN_3ADDR { MacAddr::from_slice(&frame[16..]) } else { None };
        let seq_ctrl = if len >= HDR_LEN_3ADDR {
            Some(u16::from_le_bytes([frame[22], frame[23]]))
        } else { None };
        let addr4 = if fctl::has_a4(frame_control) && fctl::is_data(frame_control) {
            MacAddr::from_slice(&frame[24..])
        } else { None };
        let qos_ctrl = if fctl::is_data_qos(frame_control) {
            let at = if fctl::has_a4(frame_control) { HDR_LEN_4ADDR } else { HDR_LEN_3ADDR };
            Some(u16::from_le_bytes([frame[at], frame[at + 1]]))
        } else { None };
        Some(Self { frame_control, duration_id, addr1, addr2, addr3, seq_ctrl, addr4,
                    qos_ctrl, len })
    }

    /// Transmitter address — who put this frame on the air. # C: O(1)
    pub fn transmitter(&self) -> Option<MacAddr> { self.addr2 }
    /// Receiver address — who the frame is addressed to on this hop. # C: O(1)
    pub fn receiver(&self) -> MacAddr { self.addr1 }

    /// Destination address, per the DS bits: the first address unless the
    /// frame is travelling toward the distribution system, in which case the
    /// third (or the third again on a four-address frame). # C: O(1)
    pub fn destination(&self) -> Option<MacAddr> {
        let fc = self.frame_control;
        if fc & fctl::FCTL_TODS != 0 { self.addr3 } else { Some(self.addr1) }
    }

    /// Source address, per the DS bits: the second address unless the frame
    /// came from the distribution system, in which case the third — or the
    /// fourth on a four-address frame. # C: O(1)
    pub fn source(&self) -> Option<MacAddr> {
        let fc = self.frame_control;
        if fctl::has_a4(fc) { return self.addr4; }
        if fc & fctl::FCTL_FROMDS != 0 { self.addr3 } else { self.addr2 }
    }

    /// BSSID, per the DS bits. A four-address frame belongs to no single BSS
    /// and reports none. # C: O(1)
    pub fn bssid(&self) -> Option<MacAddr> {
        let fc = self.frame_control;
        match (fc & fctl::FCTL_TODS != 0, fc & fctl::FCTL_FROMDS != 0) {
            (false, false) => self.addr3,
            (false, true) => self.addr2,
            (true, false) => Some(self.addr1),
            (true, true) => None,
        }
    }

    /// Sequence number, for duplicate detection and reorder windows. # C: O(1)
    pub fn seq_num(&self) -> Option<u16> { self.seq_ctrl.map(fctl::seq_to_sn) }
    /// Fragment number. # C: O(1)
    pub fn frag_num(&self) -> Option<u16> { self.seq_ctrl.map(|s| s & fctl::SCTL_FRAG) }
    /// Traffic identifier. A non-QoS frame is best effort, which the standard
    /// numbers zero. # C: O(1)
    pub fn tid(&self) -> u8 {
        self.qos_ctrl.map_or(0, |q| (q & fctl::QOS_CTL_TID_MASK) as u8)
    }
    /// Whether the QoS-control field asks for block-ack treatment. # C: O(1)
    pub fn is_blockack_policy(&self) -> bool {
        self.qos_ctrl.is_some_and(|q| q & fctl::QOS_CTL_ACK_POLICY_MASK
            == fctl::QOS_CTL_ACK_POLICY_BLOCKACK)
    }
    /// Whether the QoS-control field marks an aggregated MSDU. # C: O(1)
    pub fn is_amsdu(&self) -> bool {
        self.qos_ctrl.is_some_and(|q| q & fctl::QOS_CTL_A_MSDU_PRESENT != 0)
    }
}
