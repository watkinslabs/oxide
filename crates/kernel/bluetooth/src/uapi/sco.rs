//! SCO/eSCO wire and ABI constants: the socket address, the `SOL_SCO` options,
//! the voice-setting and codec structs, and the layouts of the synchronous
//! connection setup command, the accept command and the completion event.

use crate::uapi::bt::{BdAddr, BDADDR_LEN};

/// Payload a synchronous link carries before the controller reports its real
/// packet lengths.
pub const SCO_DEFAULT_MTU: u16 = 500;

/// `struct sockaddr_sco`: family word then address. A SCO address names no
/// channel — a peer has at most one voice link.
pub const SOCKADDR_SCO_LEN: usize = 2 + BDADDR_LEN;

/// `SOL_SCO` option numbers.
pub const SCO_OPTIONS:  u32 = 0x01;
pub const SCO_CONNINFO: u32 = 0x02;

/// `struct sco_options`: the link's payload ceiling.
pub const SCO_OPTIONS_LEN: usize = 2;
/// `struct sco_conninfo`: the underlying handle and the peer's class of device,
/// padded to the struct's two-byte alignment.
pub const SCO_CONNINFO_LEN: usize = 6;
/// Offset of the class-of-device field within it.
pub const SCO_CONNINFO_CLASS_OFF: usize = 2;
/// `struct bt_voice`: the air-coding word.
pub const BT_VOICE_LEN: usize = 2;
/// `struct bt_codec`, packed: id, company, vendor codec, data path, cap count.
pub const BT_CODEC_LEN: usize = 1 + 2 + 2 + 1 + 1;
/// `struct bt_codecs` header: the codec count that the array follows.
pub const BT_CODECS_HDR_LEN: usize = 1;

/// Codec identifiers a synchronous link selects between.
pub const BT_CODEC_CVSD:        u8 = 0x02;
pub const BT_CODEC_TRANSPARENT: u8 = 0x03;
pub const BT_CODEC_MSBC:        u8 = 0x05;

/// Bandwidth both directions of a synchronous link ask for, in octets/second.
pub const SCO_BANDWIDTH: u32 = 8000;

/// Retransmission-effort values: one retransmission for a reliable eSCO link,
/// and "no requirement" for a plain SCO link that cannot retransmit.
pub const SCO_RETRANS_POWER: u8 = 0x01;
pub const SCO_RETRANS_QUALITY: u8 = 0x02;
pub const SCO_RETRANS_DONT_CARE: u8 = 0xff;

/// Latency ceilings used by the parameter tables and the deferred accept.
pub const SCO_MAX_LATENCY_DONT_CARE: u16 = 0xffff;
pub const SCO_MAX_LATENCY_T1:        u16 = 0x0008;
pub const SCO_MAX_LATENCY_T2:        u16 = 0x000d;
pub const SCO_MAX_LATENCY_S1:        u16 = 0x0007;
pub const SCO_MAX_LATENCY_S2:        u16 = 0x0007;
pub const SCO_MAX_LATENCY_S3:        u16 = 0x000a;

/// `HCI_OP_SETUP_SYNC_CONN` parameter width.
pub const SETUP_SYNC_CONN_LEN: usize = 2 + 4 + 4 + 2 + 2 + 1 + 2;
/// `HCI_OP_ACCEPT_SYNC_CONN_REQ` parameter width.
pub const ACCEPT_SYNC_CONN_LEN: usize = BDADDR_LEN + 4 + 4 + 2 + 2 + 1 + 2;
/// `HCI_EV_SYNC_CONN_COMPLETE` payload width.
pub const SYNC_CONN_COMPLETE_LEN: usize = 1 + 2 + BDADDR_LEN + 1 + 1 + 1 + 2 + 2 + 1;

/// `struct sockaddr_sco`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct SockaddrSco {
    pub family: u16,
    pub bdaddr: BdAddr,
}

impl SockaddrSco {
    /// Decode a bind or connect address. # C: O(1)
    pub fn from_wire(buf: &[u8]) -> Option<SockaddrSco> {
        if buf.len() < SOCKADDR_SCO_LEN { return None; }
        Some(SockaddrSco { family: u16::from_le_bytes([buf[0], buf[1]]), bdaddr: BdAddr::from_wire(buf, 2)? })
    }

    /// Encode into a `getsockname`/`getpeername` buffer. # C: O(1)
    pub fn to_wire(&self, buf: &mut [u8]) -> bool {
        if buf.len() < SOCKADDR_SCO_LEN { return false; }
        buf[0..2].copy_from_slice(&self.family.to_le_bytes());
        self.bdaddr.to_wire(buf, 2)
    }
}

/// `struct bt_codec`, the codec a socket asks a synchronous link to carry.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct BtCodec {
    pub id: u8,
    pub cid: u16,
    pub vid: u16,
    pub data_path: u8,
    pub num_caps: u8,
}

impl BtCodec {
    /// Decode one packed codec descriptor. # C: O(1)
    pub fn from_wire(buf: &[u8]) -> Option<BtCodec> {
        if buf.len() < BT_CODEC_LEN { return None; }
        Some(BtCodec {
            id: buf[0],
            cid: u16::from_le_bytes([buf[1], buf[2]]),
            vid: u16::from_le_bytes([buf[3], buf[4]]),
            data_path: buf[5],
            num_caps: buf[6],
        })
    }

    /// Encode one packed codec descriptor. # C: O(1)
    pub fn to_wire(&self, buf: &mut [u8]) -> bool {
        if buf.len() < BT_CODEC_LEN { return false; }
        buf[0] = self.id;
        buf[1..3].copy_from_slice(&self.cid.to_le_bytes());
        buf[3..5].copy_from_slice(&self.vid.to_le_bytes());
        buf[5] = self.data_path;
        buf[6] = self.num_caps;
        true
    }
}

/// `HCI_EV_SYNC_CONN_COMPLETE`: what the controller reports once a synchronous
/// link is up, or why it is not.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct SyncConnComplete {
    pub status: u8,
    pub handle: u16,
    pub bdaddr: BdAddr,
    pub link_type: u8,
    pub tx_interval: u8,
    pub retrans_window: u8,
    pub rx_pkt_len: u16,
    pub tx_pkt_len: u16,
    pub air_mode: u8,
}

impl SyncConnComplete {
    /// Decode the event payload. # C: O(1)
    pub fn from_wire(buf: &[u8]) -> Option<SyncConnComplete> {
        if buf.len() < SYNC_CONN_COMPLETE_LEN { return None; }
        Some(SyncConnComplete {
            status: buf[0],
            handle: u16::from_le_bytes([buf[1], buf[2]]),
            bdaddr: BdAddr::from_wire(buf, 3)?,
            link_type: buf[9],
            tx_interval: buf[10],
            retrans_window: buf[11],
            rx_pkt_len: u16::from_le_bytes([buf[12], buf[13]]),
            tx_pkt_len: u16::from_le_bytes([buf[14], buf[15]]),
            air_mode: buf[16],
        })
    }

    /// Encode the event payload, which is what a test fixture and the monitor
    /// path both need. # C: O(1)
    pub fn to_wire(&self, buf: &mut [u8]) -> bool {
        if buf.len() < SYNC_CONN_COMPLETE_LEN { return false; }
        buf[0] = self.status;
        buf[1..3].copy_from_slice(&self.handle.to_le_bytes());
        if !self.bdaddr.to_wire(buf, 3) { return false; }
        buf[9] = self.link_type;
        buf[10] = self.tx_interval;
        buf[11] = self.retrans_window;
        buf[12..14].copy_from_slice(&self.rx_pkt_len.to_le_bytes());
        buf[14..16].copy_from_slice(&self.tx_pkt_len.to_le_bytes());
        buf[16] = self.air_mode;
        true
    }
}

#[cfg(test)]
#[path = "tests/sco.rs"]
mod tests;
