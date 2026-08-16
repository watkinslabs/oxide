// The additional authenticated data both counter-mode ciphers cover, and the
// nonce they derive from the same header.
//
// The construction is a MASKED copy of the MAC header: the fields a
// retransmission or a power-save transition may legitimately change are
// zeroed before they are authenticated, so a frame that is retried on the air
// still verifies. Getting the mask wrong does not fail loudly — it produces a
// link on which some frames verify and some do not, depending on whether the
// radio happened to set the retry bit.

extern crate alloc;

use alloc::vec::Vec;

use wireless::ieee80211::{fctl, hdr::MacHeader};

/// Widest additional authenticated data the construction produces: the
/// frame-control word, four addresses, the sequence-control field and the
/// QoS-control field.
pub const MAX_AAD_LEN: usize = 30;
/// Narrowest: a three-address frame with no QoS control.
pub const MIN_AAD_LEN: usize = 22;

/// Frame-control bits cleared before authentication because the receiver may
/// legitimately see them differ from what the sender computed over.
const MASK_CLEAR: u16 = fctl::FCTL_RETRY | fctl::FCTL_PM | fctl::FCTL_MOREDATA;
/// Subtype bits cleared on a data frame — only the low subtype bit survives,
/// so the four quality-of-service variants authenticate identically.
const MASK_SUBTYPE: u16 = 0x0070;

/// Build the additional authenticated data for one frame. Returns the bytes
/// and the traffic-identifier byte the nonce also needs, so the two cannot be
/// derived from different readings of the same header. # C: O(1)
pub fn build(header: &MacHeader) -> (Vec<u8>, u8) {
    let fc = header.frame_control;
    let mgmt = fctl::is_mgmt(fc);
    let mut mask_fc = fc & !MASK_CLEAR;
    if !mgmt { mask_fc &= !MASK_SUBTYPE; }
    mask_fc |= fctl::FCTL_PROTECTED;

    let qos_tid = if fctl::is_data_qos(fc) {
        mask_fc &= !fctl::FCTL_ORDER;
        (header.qos_ctrl.unwrap_or(0) & fctl::QOS_CTL_TID_MASK) as u8
    } else { 0 };

    let a4 = fctl::has_a4(fc);
    let mut out = Vec::with_capacity(MAX_AAD_LEN);
    out.extend_from_slice(&mask_fc.to_le_bytes());
    out.extend_from_slice(&header.addr1.0);
    out.extend_from_slice(&header.addr2.map_or([0u8; 6], |a| a.0));
    out.extend_from_slice(&header.addr3.map_or([0u8; 6], |a| a.0));
    // Only the fragment number is authenticated: the sequence number changes
    // on a retransmission of a different fragment of the same frame.
    out.push((header.seq_ctrl.unwrap_or(0) & fctl::SCTL_FRAG) as u8);
    out.push(0);
    if a4 { out.extend_from_slice(&header.addr4.map_or([0u8; 6], |a| a.0)); }
    // The QoS-control field is authenticated only when the frame carries
    // one. A four-address frame without one covers six bytes more than a
    // three-address frame and not eight.
    if fctl::is_data_qos(fc) {
        out.push(qos_tid);
        out.push(0);
    }
    (out, qos_tid)
}

/// The 13-byte nonce the counter mode with CBC-MAC takes: the flags byte
/// carrying the traffic identifier and the management marker, the
/// transmitter address, and the packet number. # C: O(1)
pub fn ccm_nonce(header: &MacHeader, qos_tid: u8, pn: &[u8; 6]) -> [u8; 13] {
    let mut out = [0u8; 13];
    out[0] = qos_tid | ((fctl::is_mgmt(header.frame_control) as u8) << 4);
    out[1..7].copy_from_slice(&header.addr2.map_or([0u8; 6], |a| a.0));
    out[7..13].copy_from_slice(pn);
    out
}

/// The 12-byte initialisation vector Galois counter mode takes: the
/// transmitter address and the packet number, with no flags byte — which is
/// why the two ciphers cannot share one nonce builder. # C: O(1)
pub fn gcm_iv(header: &MacHeader, pn: &[u8; 6]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..6].copy_from_slice(&header.addr2.map_or([0u8; 6], |a| a.0));
    out[6..12].copy_from_slice(pn);
    out
}
