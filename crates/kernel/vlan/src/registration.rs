//! The two VLAN registration applicants owned by a VLAN lower device.
//!
//! Linux keeps GVRP in the GARP applicant and MVRP in the MRP applicant.  The
//! VLAN device only supplies its VID and asks that owner to join or leave when
//! it opens, closes, or changes the corresponding flag.  This module keeps
//! that wire/state boundary in one place for both protocols.

use alloc::vec::Vec;

use net::addr::MacAddr;

pub const ETH_P_MVRP: u16 = 0x88f5;
pub const GARP_PROTOCOL_ID: u16 = 1;
pub const GARP_GROUP: MacAddr = MacAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x21]);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ApplicantKind { Gvrp, Mvrp }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Applicant {
    pub kind: ApplicantKind,
    pub joined: bool,
    pub remote: bool,
}

impl Applicant {
    pub const fn new(kind: ApplicantKind) -> Self { Self { kind, joined: false, remote: false } }
}

/// Build the first Linux applicant PDU for one VID.  Join uses the initial
/// registration event; leave uses the leave event and withdraws the local
/// attribute. # C: O(1)
pub fn pdu(kind: ApplicantKind, source: MacAddr, vid: u16, join: bool) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&GARP_GROUP.0);
    frame.extend_from_slice(&source.0);
    match kind {
        ApplicantKind::Gvrp => {
            // 802.3 length, LLC UI, GARP protocol header, one message and
            // one attribute, followed by the two GARP end marks.
            let payload_len = 3 + 2 + 1 + 4 + 2;
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
            frame.extend_from_slice(&[0x42, 0x42, 0x03]);
            frame.extend_from_slice(&GARP_PROTOCOL_ID.to_be_bytes());
            frame.extend_from_slice(&[1, 4, if join { 2 } else { 3 }]);
            frame.extend_from_slice(&vid.to_be_bytes());
            frame.extend_from_slice(&[0, 0]);
        }
        ApplicantKind::Mvrp => {
            frame.extend_from_slice(&ETH_P_MVRP.to_be_bytes());
            frame.extend_from_slice(&[0, 1, 2, 0, 1]);
            frame.extend_from_slice(&vid.to_be_bytes());
            frame.push(if join { 0 } else { 5 });
            frame.extend_from_slice(&[0, 0]);
        }
    }
    frame
}

/// Recognise a registration PDU and return its protocol, VID and event.  The
/// VLAN table calls this only for a lower device, so no second tag demux is
/// involved. # C: O(1)
pub fn parse(frame: &[u8]) -> Option<(ApplicantKind, u16, u8)> {
    if frame.len() < 14 { return None; }
    let proto = u16::from_be_bytes([frame[12], frame[13]]);
    if proto == ETH_P_MVRP {
        if frame.len() < 14 + 1 + 2 + 2 + 2 + 1 { return None; }
        if frame[14] != 0 || frame[15] != 1 || frame[16] != 2 { return None; }
        let vid = u16::from_be_bytes([frame[19], frame[20]]);
        return Some((ApplicantKind::Mvrp, vid, frame[21]));
    }
    // GVRP is an LLC SNAP-less 802.3 UI PDU.  The protocol id follows LLC.
    if proto < 0x0600 && frame.len() >= 14 + 3 + 2 + 1 + 3 + 2 {
        let p = &frame[14..];
        if p[..3] == [0x42, 0x42, 0x03]
            && u16::from_be_bytes([p[3], p[4]]) == GARP_PROTOCOL_ID
            && p[5] == 1 && p[6] == 4 {
            return Some((ApplicantKind::Gvrp, u16::from_be_bytes([p[8], p[9]]), p[7]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gvrp_join_and_leave_are_linux_shaped() {
        let source = MacAddr([2, 0, 0, 0, 0, 1]);
        for (join, event) in [(true, 2), (false, 3)] {
            let frame = pdu(ApplicantKind::Gvrp, source, 42, join);
            assert_eq!(parse(&frame), Some((ApplicantKind::Gvrp, 42, event)));
            assert_eq!(&frame[..6], &GARP_GROUP.0);
        }
    }

    #[test]
    fn mvrp_join_and_leave_are_linux_shaped() {
        let source = MacAddr([2, 0, 0, 0, 0, 1]);
        for (join, event) in [(true, 0), (false, 5)] {
            let frame = pdu(ApplicantKind::Mvrp, source, 409, join);
            assert_eq!(parse(&frame), Some((ApplicantKind::Mvrp, 409, event)));
            assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETH_P_MVRP);
        }
    }
}
