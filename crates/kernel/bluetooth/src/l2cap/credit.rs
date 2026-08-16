//! Credit-based flow control, shared by the LE and enhanced credit modes.
//!
//! A credit is permission to send exactly one PDU. Neither end may send without
//! one, and neither may grant so many that the running total leaves the range
//! the field can express — a grant that would is a protocol violation and the
//! channel goes down rather than wrapping the count.

extern crate alloc;
use alloc::vec::Vec;

use super::chan::Channel;
use crate::uapi::l2cap as u;

/// Credits this end would like the peer to hold, given how much room the
/// receive buffer has. With no estimate of that room, one PDU's worth beyond a
/// full SDU is granted so a peer is never stalled by a missing estimate.
/// # C: O(1)
pub fn le_rx_credits(chan: &Channel) -> u16 {
    if chan.mps == 0 { return 0; }
    let held = chan.le_sdu.len();
    match chan.rx_avail {
        None => (chan.imtu / chan.mps).saturating_add(1),
        Some(avail) => {
            if avail <= held { return 0; }
            let want = (avail - held).div_ceil(chan.mps as usize);
            if want > u16::MAX as usize { u16::MAX } else { want as u16 }
        }
    }
}

/// Set up credit-mode flow control. The PDU size is derived from what one
/// packet on the link carries, so a PDU never has to be fragmented by the
/// layer below. # C: O(1)
pub fn le_flowctl_init(chan: &mut Channel, tx_credits: u16, link_mtu: u16) {
    chan.le_sdu.clear();
    chan.le_sdu_len = 0;
    chan.tx_credits = tx_credits;
    chan.mps = core::cmp::min(chan.imtu, link_mtu.saturating_sub(u::HDR_SIZE as u16));
    chan.rx_credits = le_rx_credits(chan);
}

/// Set up enhanced credit-mode flow control, which additionally guarantees a
/// floor on the PDU size every implementation must support. # C: O(1)
pub fn ecred_init(chan: &mut Channel, tx_credits: u16, link_mtu: u16) {
    le_flowctl_init(chan, tx_credits, link_mtu);
    if chan.mps < u::ECRED_MIN_MPS {
        chan.mps = u::ECRED_MIN_MPS;
        chan.rx_credits = le_rx_credits(chan);
    }
}

/// The verdict on a credit grant from the peer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Grant {
    /// The grant was applied; the channel now holds this many credits.
    Applied(u16),
    /// The grant would push the running total past what the field can express.
    /// The channel must be disconnected; the count is left untouched.
    Overflow,
}

/// Apply a credit grant. # C: O(1)
pub fn grant_credits(chan: &mut Channel, credits: u16) -> Grant {
    let headroom = u::LE_MAX_CREDITS - chan.tx_credits;
    if credits > headroom { return Grant::Overflow; }
    chan.tx_credits += credits;
    Grant::Applied(chan.tx_credits)
}

/// Whether a frame may be transmitted right now. # C: O(1)
pub fn can_transmit(chan: &Channel) -> bool { chan.tx_credits > 0 }

/// Spend one credit on a transmission, reporting whether there was one to
/// spend. # C: O(1)
pub fn spend_credit(chan: &mut Channel) -> bool {
    if chan.tx_credits == 0 { return false; }
    chan.tx_credits -= 1;
    true
}

/// How many credits to grant the peer now, and the running total after doing
/// so. Nothing is granted while the peer already holds at least what the
/// receive buffer justifies. # C: O(1)
pub fn credits_to_grant(chan: &mut Channel) -> u16 {
    if !chan.is_credit_mode() { return 0; }
    let want = le_rx_credits(chan);
    if chan.rx_credits >= want { return 0; }
    let give = want - chan.rx_credits;
    chan.rx_credits += give;
    give
}

/// Transmit as many queued frames as credits allow, returning the frames that
/// went out. The rest stay queued until a grant arrives. # C: O(n)
pub fn drain_tx(chan: &mut Channel, queue: &mut Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    while chan.tx_credits > 0 && !queue.is_empty() {
        chan.tx_credits -= 1;
        sent.push(queue.remove(0));
    }
    sent
}

/// What arriving credit-mode data did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeRecv {
    /// The SDU needs more frames.
    Incomplete,
    /// A whole SDU is available.
    Complete(Vec<u8>),
    /// The peer broke the contract; the channel must be disconnected.
    Disconnect,
    /// The frame was malformed but the channel survives; the partial SDU is
    /// discarded.
    Malformed,
}

/// Take one received credit-mode frame. Every ceiling the peer agreed to is
/// enforced here — a frame with no credit behind it, one larger than the PDU
/// size, an SDU larger than the MTU, or more bytes than the SDU declared all
/// end the channel rather than being absorbed. # C: O(n)
pub fn le_data_recv(chan: &mut Channel, frame: &[u8]) -> LeRecv {
    if chan.rx_credits == 0 { return LeRecv::Disconnect; }
    if frame.len() > chan.imtu as usize { return LeRecv::Disconnect; }
    if frame.len() > chan.mps as usize { return LeRecv::Disconnect; }
    chan.rx_credits -= 1;

    if chan.le_sdu_len == 0 && chan.le_sdu.is_empty() {
        if frame.len() < u::SDULEN_SIZE { return LeRecv::Malformed; }
        let sdu_len = u16::from_le_bytes([frame[0], frame[1]]);
        let body = &frame[u::SDULEN_SIZE..];
        if sdu_len > chan.imtu { return LeRecv::Disconnect; }
        if body.len() > sdu_len as usize { return LeRecv::Malformed; }
        if body.len() == sdu_len as usize { return LeRecv::Complete(body.to_vec()); }
        chan.le_sdu = body.to_vec();
        chan.le_sdu_len = sdu_len;
        // A peer that does not fill the PDU it agreed to tells us its real
        // frame size; matching it keeps the credit accounting honest.
        let used = body.len() + u::SDULEN_SIZE;
        if (used as u16) < chan.mps { chan.mps = used as u16; }
        return LeRecv::Incomplete;
    }

    if chan.le_sdu.len() + frame.len() > chan.le_sdu_len as usize {
        chan.le_sdu.clear();
        chan.le_sdu_len = 0;
        return LeRecv::Disconnect;
    }
    chan.le_sdu.extend_from_slice(frame);
    if chan.le_sdu.len() == chan.le_sdu_len as usize {
        chan.le_sdu_len = 0;
        return LeRecv::Complete(core::mem::take(&mut chan.le_sdu));
    }
    LeRecv::Incomplete
}

/// Whether a credit-based connect request names parameters this end can work
/// with. Both figures have a floor below which the channel could not carry the
/// smallest legal payload. # C: O(1)
pub fn le_conn_params_valid(mtu: u16, mps: u16) -> bool { mtu >= u::LE_MIN_MTU && mps >= u::LE_MIN_MTU }

/// Whether an enhanced credit-based connect request names parameters this end
/// can work with. The enhanced variant raises both floors. # C: O(1)
pub fn ecred_conn_params_valid(mtu: u16, mps: u16) -> bool { mtu >= u::ECRED_MIN_MTU && mps >= u::ECRED_MIN_MPS }

/// The verdict on a reconfigure request across a set of channels. A
/// reconfiguration may not shrink an MTU any channel already uses, and may only
/// shrink the PDU size when it names exactly one channel. # C: O(n)
pub fn ecred_reconf_verdict(chans: &[(u16, u16)], mtu: u16, mps: u16) -> u16 {
    if mtu < u::ECRED_MIN_MTU { return u::RECONF_INVALID_PARAMS; }
    if mps < u::ECRED_MIN_MPS { return u::RECONF_INVALID_PARAMS; }
    if chans.len() > u::ECRED_MAX_CID { return u::RECONF_INVALID_PARAMS; }
    for (omtu, remote_mps) in chans {
        if *omtu > mtu { return u::RECONF_INVALID_MTU; }
        if *remote_mps > mps && chans.len() > 1 { return u::RECONF_INVALID_MPS; }
    }
    u::RECONF_SUCCESS
}

#[cfg(test)]
#[path = "tests/credit.rs"]
mod tests;
