//! The retransmission-mode control field, in both the 16-bit form and the
//! 32-bit extended form the extended window uses.
//!
//! One decoded shape covers both widths, so everything above this module is
//! written once; only the pack and unpack pair knows which layout is in force.

use crate::uapi::l2cap as u;

/// A decoded control field. An I-frame carries `sar` and `txseq`; an S-frame
/// carries `super_` and `poll`. The fields that do not apply to the frame kind
/// are zero, exactly as the sender left them.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Ctrl {
    /// Whether this is a supervisory frame rather than an information frame.
    pub sframe: bool,
    /// Sequence number the sender next expects from us.
    pub reqseq: u16,
    /// Sequence number of this frame, on an I-frame.
    pub txseq: u16,
    /// Segmentation state of this frame, on an I-frame.
    pub sar: u8,
    /// Supervisory function, on an S-frame.
    pub super_: u8,
    /// Poll bit: the sender is asking for a final-bit answer.
    pub poll: bool,
    /// Final bit: this frame answers a poll.
    pub final_: bool,
}

impl Ctrl {
    /// An information frame carrying `txseq` with segmentation state `sar`.
    /// # C: O(1)
    pub fn iframe(txseq: u16, sar: u8, reqseq: u16) -> Ctrl {
        Ctrl { sframe: false, txseq, sar, reqseq, ..Ctrl::default() }
    }

    /// A supervisory frame of function `super_`. # C: O(1)
    pub fn sframe(super_: u8, reqseq: u16) -> Ctrl {
        Ctrl { sframe: true, super_, reqseq, ..Ctrl::default() }
    }

    /// Decode a 16-bit control field. # C: O(1)
    pub fn unpack_enhanced(enh: u16) -> Ctrl {
        let mut c = Ctrl {
            reqseq: (enh & u::CTRL_REQSEQ) >> u::CTRL_REQSEQ_SHIFT,
            final_: enh & u::CTRL_FINAL != 0,
            ..Ctrl::default()
        };
        if enh & u::CTRL_FRAME_TYPE != 0 {
            c.sframe = true;
            c.poll = enh & u::CTRL_POLL != 0;
            c.super_ = ((enh & u::CTRL_SUPERVISE) >> u::CTRL_SUPER_SHIFT) as u8;
        } else {
            c.sar = ((enh & u::CTRL_SAR) >> u::CTRL_SAR_SHIFT) as u8;
            c.txseq = (enh & u::CTRL_TXSEQ) >> u::CTRL_TXSEQ_SHIFT;
        }
        c
    }

    /// Decode a 32-bit extended control field. # C: O(1)
    pub fn unpack_extended(ext: u32) -> Ctrl {
        let mut c = Ctrl {
            reqseq: ((ext & u::EXT_CTRL_REQSEQ) >> u::EXT_CTRL_REQSEQ_SHIFT) as u16,
            final_: ext & u::EXT_CTRL_FINAL != 0,
            ..Ctrl::default()
        };
        if ext & u::EXT_CTRL_FRAME_TYPE != 0 {
            c.sframe = true;
            c.poll = ext & u::EXT_CTRL_POLL != 0;
            c.super_ = ((ext & u::EXT_CTRL_SUPERVISE) >> u::EXT_CTRL_SUPER_SHIFT) as u8;
        } else {
            c.sar = ((ext & u::EXT_CTRL_SAR) >> u::EXT_CTRL_SAR_SHIFT) as u8;
            c.txseq = ((ext & u::EXT_CTRL_TXSEQ) >> u::EXT_CTRL_TXSEQ_SHIFT) as u16;
        }
        c
    }

    /// Encode as a 16-bit control field. # C: O(1)
    pub fn pack_enhanced(&self) -> u16 {
        let mut p = (self.reqseq << u::CTRL_REQSEQ_SHIFT) & u::CTRL_REQSEQ;
        if self.final_ { p |= u::CTRL_FINAL; }
        if self.sframe {
            if self.poll { p |= u::CTRL_POLL; }
            p |= ((self.super_ as u16) << u::CTRL_SUPER_SHIFT) & u::CTRL_SUPERVISE;
            p |= u::CTRL_FRAME_TYPE;
        } else {
            p |= ((self.sar as u16) << u::CTRL_SAR_SHIFT) & u::CTRL_SAR;
            p |= (self.txseq << u::CTRL_TXSEQ_SHIFT) & u::CTRL_TXSEQ;
        }
        p
    }

    /// Encode as a 32-bit extended control field. # C: O(1)
    pub fn pack_extended(&self) -> u32 {
        let mut p = ((self.reqseq as u32) << u::EXT_CTRL_REQSEQ_SHIFT) & u::EXT_CTRL_REQSEQ;
        if self.final_ { p |= u::EXT_CTRL_FINAL; }
        if self.sframe {
            if self.poll { p |= u::EXT_CTRL_POLL; }
            p |= ((self.super_ as u32) << u::EXT_CTRL_SUPER_SHIFT) & u::EXT_CTRL_SUPERVISE;
            p |= u::EXT_CTRL_FRAME_TYPE;
        } else {
            p |= ((self.sar as u32) << u::EXT_CTRL_SAR_SHIFT) & u::EXT_CTRL_SAR;
            p |= ((self.txseq as u32) << u::EXT_CTRL_TXSEQ_SHIFT) & u::EXT_CTRL_TXSEQ;
        }
        p
    }

    /// Decode from the front of a frame body, in whichever width is in force.
    /// # C: O(1)
    pub fn unpack(body: &[u8], ext: bool) -> Option<Ctrl> {
        if ext {
            if body.len() < u::EXT_CTRL_SIZE { return None; }
            Some(Ctrl::unpack_extended(u32::from_le_bytes([body[0], body[1], body[2], body[3]])))
        } else {
            if body.len() < u::ENH_CTRL_SIZE { return None; }
            Some(Ctrl::unpack_enhanced(u16::from_le_bytes([body[0], body[1]])))
        }
    }

    /// Encode into the width in force, least significant byte first. # C: O(1)
    pub fn pack(&self, ext: bool) -> [u8; u::EXT_CTRL_SIZE] {
        let mut out = [0u8; u::EXT_CTRL_SIZE];
        if ext { out.copy_from_slice(&self.pack_extended().to_le_bytes()); }
        else { out[..u::ENH_CTRL_SIZE].copy_from_slice(&self.pack_enhanced().to_le_bytes()); }
        out
    }
}

/// Width of the control field in force. # C: O(1)
pub fn ctrl_size(ext: bool) -> usize { if ext { u::EXT_CTRL_SIZE } else { u::ENH_CTRL_SIZE } }

/// Width of a retransmission-mode header: the basic header plus the control
/// field in force. # C: O(1)
pub fn ertm_hdr_size(ext: bool) -> usize { if ext { u::EXT_HDR_SIZE } else { u::ENH_HDR_SIZE } }

/// Largest sequence number in use, which is the window maximum. Sequence
/// arithmetic is modulo one more than this. # C: O(1)
pub fn seq_modulus(tx_win_max: u16) -> u32 { tx_win_max as u32 + 1 }

/// Distance from `seq2` forward to `seq1` in sequence space. # C: O(1)
pub fn seq_offset(tx_win_max: u16, seq1: u16, seq2: u16) -> u16 {
    if seq1 >= seq2 { seq1 - seq2 } else { (seq_modulus(tx_win_max) as u16).wrapping_sub(seq2).wrapping_add(seq1) }
}

/// The sequence number after `seq`. # C: O(1)
pub fn next_seq(tx_win_max: u16, seq: u16) -> u16 { ((seq as u32 + 1) % seq_modulus(tx_win_max)) as u16 }

#[cfg(test)]
#[path = "tests/ctrl.rs"]
mod tests;
