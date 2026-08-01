// `TCP_REPAIR_WINDOW` and `TCP_REPAIR_OPTIONS` operand shapes and their
// admission rules. Repair rewrites the connection's sequence and window state
// directly, so each field is screened against the live connection before any
// of it is installed.

use syscall::errno::Errno;
use alloc::vec::Vec;

/// `struct tcp_repair_window` — five 32-bit fields, no padding.
pub const REPAIR_WINDOW_LEN: usize = 20;
/// `struct tcp_repair_opt` — an option code and its value.
pub const REPAIR_OPT_LEN: usize = 8;

/// Wire option codes `TCP_REPAIR_OPTIONS` accepts. Any other code is skipped,
/// matching a repair image written by a newer peer.
pub const TCPOPT_MSS: u32 = 2;
pub const TCPOPT_WINDOW: u32 = 3;
pub const TCPOPT_SACK_PERM: u32 = 4;
pub const TCPOPT_TIMESTAMP: u32 = 8;

/// The send and receive window state one `TCP_REPAIR_WINDOW` call moves.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct RepairWindow {
    pub snd_wl1: u32,
    pub snd_wnd: u32,
    pub max_window: u32,
    pub rcv_wnd: u32,
    pub rcv_wup: u32,
}

impl RepairWindow {
    /// Decode the caller's buffer. # C: O(1)
    pub fn from_bytes(raw: &[u8; REPAIR_WINDOW_LEN]) -> Self {
        let w = |i: usize| u32::from_ne_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        Self { snd_wl1: w(0), snd_wnd: w(4), max_window: w(8), rcv_wnd: w(12), rcv_wup: w(16) }
    }

    /// Encode for the read direction. # C: O(1)
    pub fn to_bytes(self) -> [u8; REPAIR_WINDOW_LEN] {
        let mut out = [0u8; REPAIR_WINDOW_LEN];
        for (i, v) in [self.snd_wl1, self.snd_wnd, self.max_window, self.rcv_wnd, self.rcv_wup]
            .into_iter().enumerate()
        {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_ne_bytes());
        }
        out
    }

    /// Screen the window against the connection's next expected receive
    /// sequence. A window may not advertise more than it can hold, and neither
    /// the last window-update sequence nor the window-update mark may sit
    /// ahead of what the receiver has actually reached. # C: O(1)
    pub fn admit(self, rcv_nxt: u32) -> Result<Self, Errno> {
        if self.max_window < self.snd_wnd { return Err(Errno::Einval); }
        if after(self.snd_wl1, rcv_nxt.wrapping_add(self.rcv_wnd)) { return Err(Errno::Einval); }
        if after(self.rcv_wup, rcv_nxt) { return Err(Errno::Einval); }
        Ok(self)
    }
}

/// Sequence comparison in wrapping 32-bit sequence space. # C: O(1)
pub fn after(seq1: u32, seq2: u32) -> bool { (seq2.wrapping_sub(seq1) as i32) < 0 }

/// One decoded `struct tcp_repair_opt`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RepairOpt { pub code: u32, pub val: u32 }

impl RepairOpt {
    /// Decode the caller's buffer into whole records; a trailing partial
    /// record is ignored, which is how the option is length-terminated.
    /// # C: O(bytes)
    pub fn parse(raw: &[u8]) -> Vec<Self> {
        raw.chunks_exact(REPAIR_OPT_LEN).map(|c| Self {
            code: u32::from_ne_bytes([c[0], c[1], c[2], c[3]]),
            val: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
        }).collect()
    }
}

/// The connection state one accepted repair option installs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RepairEffect {
    /// Reset the negotiated maximum segment size.
    MssClamp(u16),
    /// Reinstall both window scales.
    WindowScale { snd: u8, rcv: u8 },
    /// Mark selective acknowledgement as negotiated.
    SackPerm,
    /// Mark timestamps as negotiated.
    Timestamps,
    /// A code this transport does not restore.
    Ignored,
}

/// Screen one repair option. An over-wide window scale cannot be represented
/// on the wire, and the two flag options carry no value, so a non-zero one is
/// a malformed image. # C: O(1)
pub fn admit_opt(opt: RepairOpt) -> Result<RepairEffect, Errno> {
    match opt.code {
        TCPOPT_MSS => Ok(RepairEffect::MssClamp(opt.val as u16)),
        TCPOPT_WINDOW => {
            let snd = opt.val & 0xFFFF;
            let rcv = opt.val >> 16;
            if snd > super::TCP_MAX_WSCALE || rcv > super::TCP_MAX_WSCALE {
                return Err(Errno::Efbig);
            }
            Ok(RepairEffect::WindowScale { snd: snd as u8, rcv: rcv as u8 })
        }
        TCPOPT_SACK_PERM => {
            if opt.val != 0 { return Err(Errno::Einval); }
            Ok(RepairEffect::SackPerm)
        }
        TCPOPT_TIMESTAMP => {
            if opt.val != 0 { return Err(Errno::Einval); }
            Ok(RepairEffect::Timestamps)
        }
        _ => Ok(RepairEffect::Ignored),
    }
}

/// Screen a whole repair-option image in order, stopping at the first bad
/// record. The prefix that already passed is returned with the error, because
/// the records before the failure are installed. # C: O(records)
pub fn admit_opts(opts: &[RepairOpt]) -> (Vec<RepairEffect>, Option<Errno>) {
    let mut out = Vec::new();
    for opt in opts {
        match admit_opt(*opt) {
            Ok(effect) => out.push(effect),
            Err(e) => return (out, Some(e)),
        }
    }
    (out, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> RepairWindow {
        RepairWindow { snd_wl1: 100, snd_wnd: 1000, max_window: 4000,
                       rcv_wnd: 500, rcv_wup: 100 }
    }

    #[test]
    fn window_bytes_round_trip_in_declared_field_order() {
        let w = window();
        let raw = w.to_bytes();
        assert_eq!(RepairWindow::from_bytes(&raw), w);
        // Field order is ABI: send side first, receive side last.
        assert_eq!(u32::from_ne_bytes(raw[0..4].try_into().unwrap()), w.snd_wl1);
        assert_eq!(u32::from_ne_bytes(raw[16..20].try_into().unwrap()), w.rcv_wup);
    }

    #[test]
    fn advertising_more_than_the_maximum_window_is_rejected() {
        let mut w = window();
        w.snd_wnd = w.max_window + 1;
        assert_eq!(w.admit(200), Err(Errno::Einval));
    }

    #[test]
    fn window_update_sequence_past_the_receive_edge_is_rejected() {
        let mut w = window();
        // rcv_nxt + rcv_wnd = 700; anything after that is out of the window.
        w.snd_wl1 = 701;
        assert_eq!(w.admit(200), Err(Errno::Einval));
        w.snd_wl1 = 700;
        assert!(w.admit(200).is_ok());
    }

    #[test]
    fn window_mark_ahead_of_the_receiver_is_rejected() {
        let mut w = window();
        w.rcv_wup = 201;
        assert_eq!(w.admit(200), Err(Errno::Einval));
        w.rcv_wup = 200;
        assert!(w.admit(200).is_ok());
    }

    #[test]
    fn sequence_comparison_wraps() {
        assert!(after(1, u32::MAX));
        assert!(!after(u32::MAX, 1));
    }

    #[test]
    fn a_trailing_partial_record_is_not_decoded() {
        let mut raw = alloc::vec![0u8; REPAIR_OPT_LEN + 3];
        raw[0] = TCPOPT_SACK_PERM as u8;
        assert_eq!(RepairOpt::parse(&raw),
            alloc::vec![RepairOpt { code: TCPOPT_SACK_PERM, val: 0 }]);
    }

    #[test]
    fn window_scale_over_the_wire_maximum_is_efbig() {
        let too_big = super::super::TCP_MAX_WSCALE + 1;
        assert_eq!(admit_opt(RepairOpt { code: TCPOPT_WINDOW, val: too_big }),
            Err(Errno::Efbig));
        assert_eq!(admit_opt(RepairOpt { code: TCPOPT_WINDOW, val: too_big << 16 }),
            Err(Errno::Efbig));
        assert_eq!(admit_opt(RepairOpt { code: TCPOPT_WINDOW, val: 0x0007_0005 }),
            Ok(RepairEffect::WindowScale { snd: 5, rcv: 7 }));
    }

    #[test]
    fn the_flag_options_must_carry_no_value() {
        assert_eq!(admit_opt(RepairOpt { code: TCPOPT_SACK_PERM, val: 1 }), Err(Errno::Einval));
        assert_eq!(admit_opt(RepairOpt { code: TCPOPT_TIMESTAMP, val: 1 }), Err(Errno::Einval));
        assert_eq!(admit_opt(RepairOpt { code: TCPOPT_SACK_PERM, val: 0 }),
            Ok(RepairEffect::SackPerm));
    }

    #[test]
    fn an_unknown_code_is_skipped_not_rejected() {
        assert_eq!(admit_opt(RepairOpt { code: 99, val: 7 }), Ok(RepairEffect::Ignored));
    }

    #[test]
    fn records_before_a_bad_one_are_still_installed() {
        let opts = [
            RepairOpt { code: TCPOPT_MSS, val: 1400 },
            RepairOpt { code: TCPOPT_WINDOW, val: super::super::TCP_MAX_WSCALE + 1 },
            RepairOpt { code: TCPOPT_SACK_PERM, val: 0 },
        ];
        let (effects, err) = admit_opts(&opts);
        assert_eq!(err, Some(Errno::Efbig));
        assert_eq!(effects, alloc::vec![RepairEffect::MssClamp(1400)]);
    }
}
