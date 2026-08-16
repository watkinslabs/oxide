//! RFCOMM wire and ABI constants: frame types, the field packing of the
//! address/control/length bytes, the multiplexer command set and its payload
//! layouts, the port-negotiation value space, the socket ABI, and the TTY
//! binding's ioctl numbers and structs.
//!
//! Packing lives here because every one of these bytes is a wire field; the
//! state machines that decide WHICH byte to send live in `crate::rfcomm`.

use crate::uapi::bt::{BdAddr, BDADDR_LEN};

/// Frame types, as carried in the control byte with the poll/final bit cleared.
pub const RFCOMM_SABM: u8 = 0x2f;
pub const RFCOMM_DISC: u8 = 0x43;
pub const RFCOMM_UA:   u8 = 0x63;
pub const RFCOMM_DM:   u8 = 0x0f;
pub const RFCOMM_UIH:  u8 = 0xef;

/// Multiplexer command types, carried in an MCC header on DLCI 0.
pub const RFCOMM_TEST:  u8 = 0x08;
pub const RFCOMM_FCON:  u8 = 0x28;
pub const RFCOMM_FCOFF: u8 = 0x18;
pub const RFCOMM_MSC:   u8 = 0x38;
pub const RFCOMM_RPN:   u8 = 0x24;
pub const RFCOMM_RLS:   u8 = 0x14;
pub const RFCOMM_PN:    u8 = 0x20;
pub const RFCOMM_NSC:   u8 = 0x04;

/// V.24 signal bits carried by a modem-status command.
pub const RFCOMM_V24_FC:  u8 = 0x02;
pub const RFCOMM_V24_RTC: u8 = 0x04;
pub const RFCOMM_V24_RTR: u8 = 0x08;
pub const RFCOMM_V24_IC:  u8 = 0x40;
pub const RFCOMM_V24_DV:  u8 = 0x80;

/// Port-negotiation bit rates.
pub const RFCOMM_RPN_BR_2400:   u8 = 0x0;
pub const RFCOMM_RPN_BR_4800:   u8 = 0x1;
pub const RFCOMM_RPN_BR_7200:   u8 = 0x2;
pub const RFCOMM_RPN_BR_9600:   u8 = 0x3;
pub const RFCOMM_RPN_BR_19200:  u8 = 0x4;
pub const RFCOMM_RPN_BR_38400:  u8 = 0x5;
pub const RFCOMM_RPN_BR_57600:  u8 = 0x6;
pub const RFCOMM_RPN_BR_115200: u8 = 0x7;
pub const RFCOMM_RPN_BR_230400: u8 = 0x8;

/// Port-negotiation character width.
pub const RFCOMM_RPN_DATA_5: u8 = 0x0;
pub const RFCOMM_RPN_DATA_6: u8 = 0x1;
pub const RFCOMM_RPN_DATA_7: u8 = 0x2;
pub const RFCOMM_RPN_DATA_8: u8 = 0x3;

/// Port-negotiation stop bits: one, or one and a half.
pub const RFCOMM_RPN_STOP_1:  u8 = 0;
pub const RFCOMM_RPN_STOP_15: u8 = 1;

/// Port-negotiation parity.
pub const RFCOMM_RPN_PARITY_NONE:  u8 = 0x0;
pub const RFCOMM_RPN_PARITY_ODD:   u8 = 0x1;
pub const RFCOMM_RPN_PARITY_EVEN:  u8 = 0x3;
pub const RFCOMM_RPN_PARITY_MARK:  u8 = 0x5;
pub const RFCOMM_RPN_PARITY_SPACE: u8 = 0x7;

/// Port-negotiation flow control and the software flow-control characters.
pub const RFCOMM_RPN_FLOW_NONE: u8 = 0x00;
pub const RFCOMM_RPN_XON_CHAR:  u8 = 0x11;
pub const RFCOMM_RPN_XOFF_CHAR: u8 = 0x13;

/// Port-negotiation parameter mask. A parameter whose bit is clear is not being
/// negotiated and keeps whatever value the port already has.
pub const RFCOMM_RPN_PM_BITRATE:     u16 = 0x0001;
pub const RFCOMM_RPN_PM_DATA:        u16 = 0x0002;
pub const RFCOMM_RPN_PM_STOP:        u16 = 0x0004;
pub const RFCOMM_RPN_PM_PARITY:      u16 = 0x0008;
pub const RFCOMM_RPN_PM_PARITY_TYPE: u16 = 0x0010;
pub const RFCOMM_RPN_PM_XON:         u16 = 0x0020;
pub const RFCOMM_RPN_PM_XOFF:        u16 = 0x0040;
pub const RFCOMM_RPN_PM_FLOW:        u16 = 0x3F00;
pub const RFCOMM_RPN_PM_ALL:         u16 = 0x3F7F;

/// Default per-DLC parameters before any negotiation.
pub const RFCOMM_DEFAULT_MTU:     u16 = 127;
pub const RFCOMM_DEFAULT_CREDITS: u8  = 7;
/// Credit ceiling once credit-based flow control is on. Doubles as the enabled
/// marker of the CFC tri-state, which is why it is a credit count and not 1.
pub const RFCOMM_MAX_CREDITS:     u8  = 40;

/// Credit-flow tri-state. Unknown means the session has not yet negotiated,
/// which is distinct from having negotiated it off.
pub const RFCOMM_CFC_UNKNOWN:  i16 = -1;
pub const RFCOMM_CFC_DISABLED: i16 = 0;
pub const RFCOMM_CFC_ENABLED:  i16 = RFCOMM_MAX_CREDITS as i16;

/// Parameter-negotiation flow-control field values that turn credit flow on: a
/// request carries one value and its response the other.
pub const RFCOMM_PN_CFC_REQ: u8 = 0xf0;
pub const RFCOMM_PN_CFC_RSP: u8 = 0xe0;

/// Largest length expressible in the one-byte length field.
pub const RFCOMM_LEN8_MAX: usize = 127;
/// Largest test-command pattern that fits one frame.
pub const RFCOMM_TEST_PATTERN_MAX: usize = 125;

/// Server channel range. Channel 0 is the multiplexer's own control channel and
/// 31 has no DLCI, so a data channel is 1..=30 and a data DLCI is 2..=61.
pub const RFCOMM_CHANNEL_MIN: u8 = 1;
pub const RFCOMM_CHANNEL_MAX: u8 = 30;

/// Timeouts, in milliseconds.
pub const RFCOMM_CONN_TIMEOUT_MS: u64 = 30_000;
pub const RFCOMM_DISC_TIMEOUT_MS: u64 = 20_000;
pub const RFCOMM_AUTH_TIMEOUT_MS: u64 = 25_000;
pub const RFCOMM_IDLE_TIMEOUT_MS: u64 = 2_000;

/// DLC and session flag bit positions.
pub const RFCOMM_RX_THROTTLED: u32 = 0;
pub const RFCOMM_TX_THROTTLED: u32 = 1;
pub const RFCOMM_TIMED_OUT:    u32 = 2;
pub const RFCOMM_MSC_PENDING:  u32 = 3;
pub const RFCOMM_SEC_PENDING:  u32 = 4;
pub const RFCOMM_AUTH_PENDING: u32 = 5;
pub const RFCOMM_AUTH_ACCEPT:  u32 = 6;
pub const RFCOMM_AUTH_REJECT:  u32 = 7;
pub const RFCOMM_DEFER_SETUP:  u32 = 8;
pub const RFCOMM_ENC_DROP:     u32 = 9;
pub const RFCOMM_SCHED_WAKEUP: u32 = 31;

/// Modem-status exchange progress: each direction is one bit and the DLC only
/// carries data once both have been seen.
pub const RFCOMM_MSCEX_TX: u8 = 1;
pub const RFCOMM_MSCEX_RX: u8 = 2;
pub const RFCOMM_MSCEX_OK: u8 = RFCOMM_MSCEX_TX + RFCOMM_MSCEX_RX;

/// Widths of the multiplexer command payloads.
pub const RFCOMM_PN_LEN:  usize = 8;
pub const RFCOMM_RPN_LEN: usize = 8;
pub const RFCOMM_RLS_LEN: usize = 2;
pub const RFCOMM_MSC_LEN: usize = 2;
/// MCC header: the type byte and the length byte.
pub const RFCOMM_MCC_LEN: usize = 2;

/// `struct sockaddr_rc`: family word, address, server channel, then one byte of
/// tail padding to the struct's two-byte alignment.
pub const SOCKADDR_RC_LEN: usize = 10;
/// Offset of the server channel within it.
pub const SOCKADDR_RC_CHANNEL_OFF: usize = 2 + BDADDR_LEN;

/// `SOL_RFCOMM` option numbers.
pub const RFCOMM_CONNINFO: u32 = 0x02;
pub const RFCOMM_LM:       u32 = 0x03;

/// `struct rfcomm_conninfo`: the handle of the underlying link and the peer's
/// class of device, padded to the struct's two-byte alignment.
pub const RFCOMM_CONNINFO_LEN: usize = 6;

/// `RFCOMM_LM` link-mode bits.
pub const RFCOMM_LM_MASTER:   u32 = 0x0001;
pub const RFCOMM_LM_AUTH:     u32 = 0x0002;
pub const RFCOMM_LM_ENCRYPT:  u32 = 0x0004;
pub const RFCOMM_LM_TRUSTED:  u32 = 0x0008;
pub const RFCOMM_LM_RELIABLE: u32 = 0x0010;
pub const RFCOMM_LM_SECURE:   u32 = 0x0020;
pub const RFCOMM_LM_FIPS:     u32 = 0x0040;

/// TTY binding ioctls, `_IOW('R', n, int)` and `_IOR('R', n, int)`.
pub const RFCOMMCREATEDEV:  u32 = 0x400452c8;
pub const RFCOMMRELEASEDEV: u32 = 0x400452c9;
pub const RFCOMMGETDEVLIST: u32 = 0x800452d2;
pub const RFCOMMGETDEVINFO: u32 = 0x800452d3;
pub const RFCOMMSTEALDLC:   u32 = 0x400452dc;

/// TTY binding limits and node numbering.
pub const RFCOMM_MAX_DEV:    i16 = 256;
pub const RFCOMM_TTY_MAJOR:  u32 = 216;
pub const RFCOMM_TTY_MINOR:  u32 = 0;

/// `rfcomm_dev.flags` bit positions, visible to userspace through the ioctls.
pub const RFCOMM_REUSE_DLC:     u32 = 0;
pub const RFCOMM_RELEASE_ONHUP: u32 = 1;
pub const RFCOMM_HANGUP_NOW:    u32 = 2;
pub const RFCOMM_TTY_ATTACHED:  u32 = 3;

/// `rfcomm_dev.status` bit positions, kernel-internal.
pub const RFCOMM_DEV_RELEASED: u32 = 0;
pub const RFCOMM_TTY_OWNED:    u32 = 1;

/// The exact flag word a create or release may carry without `CAP_NET_ADMIN`.
/// Equality, not a subset test: any other bit demands the capability.
pub const RFCOMM_NOCAP_FLAGS: u32 = (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP);

/// The flag bits a device retains out of a create request; the rest describe the
/// request rather than the device.
pub const RFCOMM_DEV_FLAG_MASK: u32 = (1 << RFCOMM_RELEASE_ONHUP) | (1 << RFCOMM_REUSE_DLC);

/// `struct rfcomm_dev_req`. None of these structs is packed, so each carries the
/// padding its four-byte alignment demands: two bytes after the identifier and
/// three at the tail. Encoding them densely shifts every field after the
/// identifier and is not detectable from the ioctl number.
pub const RFCOMM_DEV_REQ_LEN: usize = 24;
pub const DEV_REQ_ID_OFF:      usize = 0;
pub const DEV_REQ_FLAGS_OFF:   usize = 4;
pub const DEV_REQ_SRC_OFF:     usize = 8;
pub const DEV_REQ_DST_OFF:     usize = 14;
pub const DEV_REQ_CHANNEL_OFF: usize = 20;

/// `struct rfcomm_dev_info`.
pub const RFCOMM_DEV_INFO_LEN: usize = 24;
pub const DEV_INFO_ID_OFF:      usize = 0;
pub const DEV_INFO_FLAGS_OFF:   usize = 4;
pub const DEV_INFO_STATE_OFF:   usize = 8;
pub const DEV_INFO_SRC_OFF:     usize = 10;
pub const DEV_INFO_DST_OFF:     usize = 16;
pub const DEV_INFO_CHANNEL_OFF: usize = 22;

/// `struct rfcomm_dev_list_req`: the count, then padding to the alignment of the
/// info array that follows.
pub const RFCOMM_DEV_LIST_HDR_LEN: usize = 4;

/// Extended-address bit of a length or address byte: set means the field ends
/// here. # C: O(1)
pub fn test_ea(b: u8) -> bool { b & 0x01 != 0 }

/// Command/response bit of an address or MCC type byte. # C: O(1)
pub fn test_cr(b: u8) -> bool { b & 0x02 != 0 }

/// Poll/final bit of a control byte. # C: O(1)
pub fn test_pf(b: u8) -> bool { b & 0x10 != 0 }

/// Pack an address byte from the command/response bit and the DLCI. # C: O(1)
pub fn addr(cr: bool, dlci: u8) -> u8 { ((dlci & 0x3f) << 2) | ((cr as u8) << 1) | 0x01 }

/// The DLCI carried by an address byte. # C: O(1)
pub fn get_dlci(b: u8) -> u8 { (b & 0xfc) >> 2 }

/// Pack a control byte from the frame type and the poll/final bit. # C: O(1)
pub fn ctrl(ftype: u8, pf: bool) -> u8 { (ftype & 0xef) | ((pf as u8) << 4) }

/// The frame type carried by a control byte, with the poll/final bit masked
/// out. # C: O(1)
pub fn get_type(b: u8) -> u8 { b & 0xef }

/// The DLCI of a server channel in one direction of a session. # C: O(1)
pub fn dlci(dir: u8, chn: u8) -> u8 { ((chn & 0x1f) << 1) | (dir & 0x01) }

/// The server channel a DLCI belongs to. # C: O(1)
pub fn srv_channel(dlci: u8) -> u8 { dlci >> 1 }

/// The direction bit a session uses for the DLCIs it opens: an initiator's
/// channels are even, a responder's odd. # C: O(1)
pub fn session_dir(initiator: bool) -> u8 { if initiator { 0x00 } else { 0x01 } }

/// One-byte length field, extended-address bit set. # C: O(1)
pub fn len8(len: usize) -> u8 { ((len as u8) << 1) | 1 }

/// Low byte of a two-byte length field, extended-address bit clear. # C: O(1)
pub fn len16_lo(len: usize) -> u8 { (len as u8) << 1 }

/// High byte of a two-byte length field. # C: O(1)
pub fn len16_hi(len: usize) -> u8 { (len >> 7) as u8 }

/// Length carried by a one-byte length field. # C: O(1)
pub fn get_len8(b: u8) -> usize { (b >> 1) as usize }

/// Length carried by a two-byte length field. # C: O(1)
pub fn get_len16(lo: u8, hi: u8) -> usize { ((lo >> 1) as usize) | ((hi as usize) << 7) }

/// Pack an MCC type byte from the command/response bit and the command.
/// # C: O(1)
pub fn mcc_type(cr: bool, ty: u8) -> u8 { (ty << 2) | ((cr as u8) << 1) | 0x01 }

/// The command carried by an MCC type byte. # C: O(1)
pub fn get_mcc_type(b: u8) -> u8 { (b & 0xfc) >> 2 }

/// The payload length carried by an MCC length byte. # C: O(1)
pub fn get_mcc_len(b: u8) -> usize { ((b & 0xfe) >> 1) as usize }

/// Pack the line-settings byte of a port-negotiation payload. # C: O(1)
pub fn rpn_line_settings(data: u8, stop: u8, parity: u8) -> u8 {
    (data & 0x3) | ((stop & 0x1) << 2) | ((parity & 0x7) << 3)
}

/// Character width carried by a line-settings byte. # C: O(1)
pub fn get_rpn_data_bits(line: u8) -> u8 { line & 0x3 }

/// Stop bits carried by a line-settings byte. # C: O(1)
pub fn get_rpn_stop_bits(line: u8) -> u8 { (line >> 2) & 0x1 }

/// Parity carried by a line-settings byte. # C: O(1)
pub fn get_rpn_parity(line: u8) -> u8 { (line >> 3) & 0x7 }

/// Whether a server channel names a usable data channel. # C: O(1)
pub fn channel_valid(channel: u8) -> bool {
    channel >= RFCOMM_CHANNEL_MIN && channel <= RFCOMM_CHANNEL_MAX
}

/// `struct sockaddr_rc`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct SockaddrRc {
    pub family: u16,
    pub bdaddr: BdAddr,
    pub channel: u8,
}

impl SockaddrRc {
    /// Decode a bound or connect address. A buffer shorter than the struct is
    /// rejected rather than zero-extended, because a short address would name
    /// channel 0 — the control channel — by accident. # C: O(1)
    pub fn from_wire(buf: &[u8]) -> Option<SockaddrRc> {
        if buf.len() < SOCKADDR_RC_LEN { return None; }
        Some(SockaddrRc {
            family: u16::from_le_bytes([buf[0], buf[1]]),
            bdaddr: BdAddr::from_wire(buf, 2)?,
            channel: buf[SOCKADDR_RC_CHANNEL_OFF],
        })
    }

    /// Encode into a `getsockname`/`getpeername` buffer. # C: O(1)
    pub fn to_wire(&self, buf: &mut [u8]) -> bool {
        if buf.len() < SOCKADDR_RC_LEN { return false; }
        buf[0..SOCKADDR_RC_LEN].fill(0);
        buf[0..2].copy_from_slice(&self.family.to_le_bytes());
        if !self.bdaddr.to_wire(buf, 2) { return false; }
        buf[SOCKADDR_RC_CHANNEL_OFF] = self.channel;
        true
    }
}

#[cfg(test)]
#[path = "tests/rfcomm.rs"]
mod tests;
