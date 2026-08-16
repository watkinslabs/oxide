//! Family-wide `AF_BLUETOOTH` ABI: the address, the protocol selectors, the
//! `SOL_BLUETOOTH` option numbers every protocol shares, and the socket state
//! enumeration L2CAP, RFCOMM and SCO all report through.

/// `AF_BLUETOOTH`/`PF_BLUETOOTH`.
pub const AF_BLUETOOTH: u32 = 31;

/// Protocol selector, third argument of `socket(AF_BLUETOOTH, ...)`.
pub const BTPROTO_L2CAP:  u32 = 0;
pub const BTPROTO_HCI:    u32 = 1;
pub const BTPROTO_SCO:    u32 = 2;
pub const BTPROTO_RFCOMM: u32 = 3;
pub const BTPROTO_BNEP:   u32 = 4;
pub const BTPROTO_CMTP:   u32 = 5;
pub const BTPROTO_HIDP:   u32 = 6;
pub const BTPROTO_AVDTP:  u32 = 7;
pub const BTPROTO_ISO:    u32 = 8;
pub const BTPROTO_LAST:   u32 = BTPROTO_ISO;

/// Per-protocol `setsockopt` levels.
pub const SOL_HCI:       u32 = 0;
pub const SOL_L2CAP:     u32 = 6;
pub const SOL_SCO:       u32 = 17;
pub const SOL_RFCOMM:    u32 = 18;
/// Family-wide option level, shared by every protocol.
pub const SOL_BLUETOOTH: u32 = 274;

/// `SOL_BLUETOOTH` option numbers.
pub const BT_SECURITY:       u32 = 4;
pub const BT_DEFER_SETUP:    u32 = 7;
pub const BT_FLUSHABLE:      u32 = 8;
pub const BT_POWER:          u32 = 9;
pub const BT_CHANNEL_POLICY: u32 = 10;
pub const BT_VOICE:          u32 = 11;
pub const BT_SNDMTU:         u32 = 12;
pub const BT_RCVMTU:         u32 = 13;
pub const BT_PHY:            u32 = 14;
pub const BT_MODE:           u32 = 15;
pub const BT_PKT_STATUS:     u32 = 16;
pub const BT_ISO_QOS:        u32 = 17;
pub const BT_CODEC:          u32 = 19;

/// `BT_SECURITY` levels, ordered so a numeric comparison is the sufficiency test.
pub const BT_SECURITY_SDP:    u8 = 0;
pub const BT_SECURITY_LOW:    u8 = 1;
pub const BT_SECURITY_MEDIUM: u8 = 2;
pub const BT_SECURITY_HIGH:   u8 = 3;
pub const BT_SECURITY_FIPS:   u8 = 4;

/// `struct bt_security` payload width: level byte then key-size byte.
pub const BT_SECURITY_LEN: usize = 2;

pub const BT_FLUSHABLE_OFF: u32 = 0;
pub const BT_FLUSHABLE_ON:  u32 = 1;

pub const BT_POWER_FORCE_ACTIVE_OFF: u8 = 0;
pub const BT_POWER_FORCE_ACTIVE_ON:  u8 = 1;

pub const BT_CHANNEL_POLICY_BREDR_ONLY:      u32 = 0;
pub const BT_CHANNEL_POLICY_BREDR_PREFERRED: u32 = 1;
pub const BT_CHANNEL_POLICY_AMP_PREFERRED:   u32 = 2;

/// `BT_MODE` values — the L2CAP transmission mode a socket asks for.
pub const BT_MODE_BASIC:        u8 = 0x00;
pub const BT_MODE_ERTM:         u8 = 0x01;
pub const BT_MODE_STREAMING:    u8 = 0x02;
pub const BT_MODE_LE_FLOWCTL:   u8 = 0x03;
pub const BT_MODE_EXT_FLOWCTL:  u8 = 0x04;

/// `BT_VOICE` settings: the air-coding a SCO link asks the controller for.
pub const BT_VOICE_TRANSPARENT:       u16 = 0x0003;
pub const BT_VOICE_CVSD_16BIT:        u16 = 0x0060;
pub const BT_VOICE_TRANSPARENT_16BIT: u16 = 0x0063;

/// Ancillary message types a Bluetooth socket attaches to a received packet.
pub const BT_SCM_PKT_STATUS: u32 = 0x03;
pub const BT_SCM_ERROR:      u32 = 0x04;

/// Address types. A BR/EDR address and an LE public address with the same six
/// bytes are DIFFERENT peers; every lookup keys on the pair.
pub const BDADDR_BREDR:     u8 = 0x00;
pub const BDADDR_LE_PUBLIC: u8 = 0x01;
pub const BDADDR_LE_RANDOM: u8 = 0x02;

/// Socket/channel state, shared by every protocol's state field. `BT_CONNECTED`
/// is 1 because it aliases the TCP established state the socket layer reports.
pub const BT_CONNECTED: u8 = 1;
pub const BT_OPEN:      u8 = 2;
pub const BT_BOUND:     u8 = 3;
pub const BT_LISTEN:    u8 = 4;
pub const BT_CONNECT:   u8 = 5;
pub const BT_CONNECT2:  u8 = 6;
pub const BT_CONFIG:    u8 = 7;
pub const BT_DISCONN:   u8 = 8;
pub const BT_CLOSED:    u8 = 9;

/// Width of a device address on the wire and in every ABI struct.
pub const BDADDR_LEN: usize = 6;

/// A Bluetooth device address. Stored, transmitted and compared in the
/// wire order — least significant byte first — so a copy in or out of an ABI
/// struct is a straight `copy_from_slice`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct BdAddr(pub [u8; BDADDR_LEN]);

/// The all-zero address. A controller reporting it has no assigned identity,
/// which is why an unconfigured controller cannot be brought up.
pub const BDADDR_ANY: BdAddr = BdAddr([0; BDADDR_LEN]);

impl BdAddr {
    /// Read an address out of a wire buffer at `off`. # C: O(1)
    pub fn from_wire(buf: &[u8], off: usize) -> Option<BdAddr> {
        let end = off.checked_add(BDADDR_LEN)?;
        if end > buf.len() { return None; }
        let mut a = [0u8; BDADDR_LEN];
        a.copy_from_slice(&buf[off..end]);
        Some(BdAddr(a))
    }

    /// Write the address into a wire buffer at `off`. # C: O(1)
    pub fn to_wire(&self, buf: &mut [u8], off: usize) -> bool {
        let Some(end) = off.checked_add(BDADDR_LEN) else { return false; };
        if end > buf.len() { return false; }
        buf[off..end].copy_from_slice(&self.0);
        true
    }

    /// Whether the address is the all-zero one. # C: O(1)
    pub fn is_any(&self) -> bool { self.0 == BDADDR_ANY.0 }

    /// Raw bytes in wire order. # C: O(1)
    pub fn as_bytes(&self) -> &[u8; BDADDR_LEN] { &self.0 }
}

/// Whether a protocol selector names a protocol this family serves. A selector
/// past the last defined one is out of range rather than unsupported. # C: O(1)
pub fn protocol_in_range(protocol: u32) -> bool { protocol <= BTPROTO_LAST }

/// Whether a security level operand names a real level. # C: O(1)
pub fn security_level_valid(level: u8) -> bool { level <= BT_SECURITY_FIPS }

#[cfg(test)]
#[path = "tests/bt.rs"]
mod tests;
