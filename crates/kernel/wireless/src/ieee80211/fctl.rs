// Frame-control, sequence-control and QoS-control bit layout. Every field is
// little-endian on the air.

/// Protocol-version field. A frame with a non-zero version is not one this
/// standard describes and is dropped before anything reads its addresses.
pub const FCTL_VERS: u16 = 0x0003;
/// Frame type field.
pub const FCTL_FTYPE: u16 = 0x000c;
/// Frame subtype field.
pub const FCTL_STYPE: u16 = 0x00f0;
/// Type and subtype together — what selects a handler.
pub const FCTL_TYPE: u16 = FCTL_FTYPE | FCTL_STYPE;
pub const FCTL_TODS: u16 = 0x0100;
pub const FCTL_FROMDS: u16 = 0x0200;
pub const FCTL_MOREFRAGS: u16 = 0x0400;
pub const FCTL_RETRY: u16 = 0x0800;
pub const FCTL_PM: u16 = 0x1000;
pub const FCTL_MOREDATA: u16 = 0x2000;
pub const FCTL_PROTECTED: u16 = 0x4000;
pub const FCTL_ORDER: u16 = 0x8000;

pub const FTYPE_MGMT: u16 = 0x0000;
pub const FTYPE_CTL: u16 = 0x0004;
pub const FTYPE_DATA: u16 = 0x0008;
pub const FTYPE_EXT: u16 = 0x000c;

/// Management subtypes.
pub mod mgmt_stype {
    pub const ASSOC_REQ: u16 = 0x0000;
    pub const ASSOC_RESP: u16 = 0x0010;
    pub const REASSOC_REQ: u16 = 0x0020;
    pub const REASSOC_RESP: u16 = 0x0030;
    pub const PROBE_REQ: u16 = 0x0040;
    pub const PROBE_RESP: u16 = 0x0050;
    pub const BEACON: u16 = 0x0080;
    pub const ATIM: u16 = 0x0090;
    pub const DISASSOC: u16 = 0x00a0;
    pub const AUTH: u16 = 0x00b0;
    pub const DEAUTH: u16 = 0x00c0;
    pub const ACTION: u16 = 0x00d0;
}

/// Control subtypes.
pub mod ctl_stype {
    pub const TRIGGER: u16 = 0x0020;
    pub const CTL_EXT: u16 = 0x0060;
    pub const BACK_REQ: u16 = 0x0080;
    pub const BACK: u16 = 0x0090;
    pub const PSPOLL: u16 = 0x00a0;
    pub const RTS: u16 = 0x00b0;
    pub const CTS: u16 = 0x00c0;
    pub const ACK: u16 = 0x00d0;
    pub const CFEND: u16 = 0x00e0;
    pub const CFENDACK: u16 = 0x00f0;
}

/// Data subtypes. Bit `0x0040` marks a frame with no payload and `0x0080`
/// marks a QoS frame, which is why the QoS-control field's presence is a bit
/// test and not a table lookup.
pub mod data_stype {
    pub const DATA: u16 = 0x0000;
    pub const DATA_CFACK: u16 = 0x0010;
    pub const DATA_CFPOLL: u16 = 0x0020;
    pub const DATA_CFACKPOLL: u16 = 0x0030;
    pub const NULLFUNC: u16 = 0x0040;
    pub const CFACK: u16 = 0x0050;
    pub const CFPOLL: u16 = 0x0060;
    pub const CFACKPOLL: u16 = 0x0070;
    pub const QOS_DATA: u16 = 0x0080;
    pub const QOS_DATA_CFACK: u16 = 0x0090;
    pub const QOS_DATA_CFPOLL: u16 = 0x00a0;
    pub const QOS_DATA_CFACKPOLL: u16 = 0x00b0;
    pub const QOS_NULLFUNC: u16 = 0x00c0;
    /// Set in every QoS data subtype.
    pub const QOS: u16 = 0x0080;
    /// Set in every subtype that carries no payload.
    pub const NODATA: u16 = 0x0040;
}

/// Sequence-control fragment number field.
pub const SCTL_FRAG: u16 = 0x000f;
/// Sequence-control sequence number field.
pub const SCTL_SEQ: u16 = 0xfff0;
/// Sequence numbers wrap here; every window comparison is modulo this.
pub const SEQ_MODULO: u16 = 4096;

/// Sequence number carried in a sequence-control field. # C: O(1)
pub fn seq_to_sn(seq: u16) -> u16 { (seq & SCTL_SEQ) >> 4 }
/// Sequence-control field carrying a sequence number and fragment number.
/// # C: O(1)
pub fn sn_to_seq(sn: u16, frag: u16) -> u16 { ((sn << 4) & SCTL_SEQ) | (frag & SCTL_FRAG) }

/// QoS-control field width.
pub const QOS_CTL_LEN: usize = 2;
pub const QOS_CTL_TID_MASK: u16 = 0x000f;
pub const QOS_CTL_EOSP: u16 = 0x0010;
pub const QOS_CTL_ACK_POLICY_MASK: u16 = 0x0060;
pub const QOS_CTL_ACK_POLICY_NORMAL: u16 = 0x0000;
pub const QOS_CTL_ACK_POLICY_NOACK: u16 = 0x0020;
pub const QOS_CTL_ACK_POLICY_NO_EXPL: u16 = 0x0040;
pub const QOS_CTL_ACK_POLICY_BLOCKACK: u16 = 0x0060;
pub const QOS_CTL_A_MSDU_PRESENT: u16 = 0x0080;

/// Traffic identifiers a QoS frame can carry.
pub const NUM_TIDS: usize = 16;
/// Traffic identifiers block ack covers.
pub const NUM_BA_TIDS: usize = 8;

/// HT-control field width, present when the order bit is set on a QoS frame.
pub const HT_CTL_LEN: usize = 4;

/// Frame type of a frame-control word. # C: O(1)
pub fn ftype(fc: u16) -> u16 { fc & FCTL_FTYPE }
/// Subtype of a frame-control word. # C: O(1)
pub fn stype(fc: u16) -> u16 { fc & FCTL_STYPE }
/// Type and subtype together. # C: O(1)
pub fn frame_type(fc: u16) -> u16 { fc & FCTL_TYPE }

/// Frame is management. # C: O(1)
pub fn is_mgmt(fc: u16) -> bool { ftype(fc) == FTYPE_MGMT }
/// Frame is control. # C: O(1)
pub fn is_ctl(fc: u16) -> bool { ftype(fc) == FTYPE_CTL }
/// Frame is data. # C: O(1)
pub fn is_data(fc: u16) -> bool { ftype(fc) == FTYPE_DATA }
/// Frame is a QoS data frame, so its header carries a QoS-control field.
/// # C: O(1)
pub fn is_data_qos(fc: u16) -> bool { is_data(fc) && stype(fc) & data_stype::QOS != 0 }
/// Frame carries no payload. # C: O(1)
pub fn is_nodata(fc: u16) -> bool { is_data(fc) && stype(fc) & data_stype::NODATA != 0 }
/// Frame has a four-address header — both DS bits set. # C: O(1)
pub fn has_a4(fc: u16) -> bool { fc & (FCTL_TODS | FCTL_FROMDS) == (FCTL_TODS | FCTL_FROMDS) }
/// Frame is a beacon. # C: O(1)
pub fn is_beacon(fc: u16) -> bool { frame_type(fc) == FTYPE_MGMT | mgmt_stype::BEACON }
/// Frame is a probe response. # C: O(1)
pub fn is_probe_resp(fc: u16) -> bool { frame_type(fc) == FTYPE_MGMT | mgmt_stype::PROBE_RESP }
/// Frame carries a protected payload. # C: O(1)
pub fn is_protected(fc: u16) -> bool { fc & FCTL_PROTECTED != 0 }
/// Frame is a robust management frame — the class management-frame protection
/// covers. Association and probe exchanges are excluded; deauthenticate,
/// disassociate and most action frames are not. # C: O(1)
pub fn is_robust_mgmt(fc: u16) -> bool {
    if !is_mgmt(fc) { return false; }
    matches!(stype(fc), mgmt_stype::DEAUTH | mgmt_stype::DISASSOC | mgmt_stype::ACTION)
}
