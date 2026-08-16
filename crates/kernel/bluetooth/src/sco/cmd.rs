//! Synchronous-connection setup and accept commands.
//!
//! Both carry the same negotiated quantities under different names — the
//! outgoing command names the voice setting, the accept names the content
//! format — and both ask for the same bandwidth in each direction.

use alloc::vec::Vec;

use crate::uapi::bt::BdAddr;
use crate::uapi::sco as u;
use super::param::ScoParam;

/// `HCI_OP_SETUP_SYNC_CONN` parameters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetupSyncConn {
    pub handle: u16,
    pub tx_bandwidth: u32,
    pub rx_bandwidth: u32,
    pub max_latency: u16,
    pub voice_setting: u16,
    pub retrans_effort: u8,
    pub pkt_type: u16,
}

impl SetupSyncConn {
    /// The command for one attempt at a link: the chosen row's parameters, the
    /// requested voice setting, and the standard bandwidth. # C: O(1)
    pub fn new(handle: u16, setting: u16, param: &ScoParam) -> SetupSyncConn {
        SetupSyncConn {
            handle,
            tx_bandwidth: u::SCO_BANDWIDTH,
            rx_bandwidth: u::SCO_BANDWIDTH,
            max_latency: param.max_latency,
            voice_setting: setting,
            retrans_effort: param.retrans_effort,
            pkt_type: param.pkt_type,
        }
    }

    /// Encode the parameters. # C: O(1)
    pub fn to_wire(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(u::SETUP_SYNC_CONN_LEN);
        v.extend_from_slice(&self.handle.to_le_bytes());
        v.extend_from_slice(&self.tx_bandwidth.to_le_bytes());
        v.extend_from_slice(&self.rx_bandwidth.to_le_bytes());
        v.extend_from_slice(&self.max_latency.to_le_bytes());
        v.extend_from_slice(&self.voice_setting.to_le_bytes());
        v.push(self.retrans_effort);
        v.extend_from_slice(&self.pkt_type.to_le_bytes());
        v
    }

    /// Decode the parameters, which is what a test and the monitor path read.
    /// # C: O(1)
    pub fn from_wire(b: &[u8]) -> Option<SetupSyncConn> {
        if b.len() < u::SETUP_SYNC_CONN_LEN { return None; }
        Some(SetupSyncConn {
            handle: u16::from_le_bytes([b[0], b[1]]),
            tx_bandwidth: u32::from_le_bytes([b[2], b[3], b[4], b[5]]),
            rx_bandwidth: u32::from_le_bytes([b[6], b[7], b[8], b[9]]),
            max_latency: u16::from_le_bytes([b[10], b[11]]),
            voice_setting: u16::from_le_bytes([b[12], b[13]]),
            retrans_effort: b[14],
            pkt_type: u16::from_le_bytes([b[15], b[16]]),
        })
    }
}

/// `HCI_OP_ACCEPT_SYNC_CONN_REQ` parameters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AcceptSyncConn {
    pub bdaddr: BdAddr,
    pub tx_bandwidth: u32,
    pub rx_bandwidth: u32,
    pub max_latency: u16,
    pub content_format: u16,
    pub retrans_effort: u8,
    pub pkt_type: u16,
}

impl AcceptSyncConn {
    /// The command answering an inbound request, with the latency and effort the
    /// air coding demands. # C: O(1)
    pub fn new(bdaddr: BdAddr, setting: u16, pkt_type: u16) -> AcceptSyncConn {
        let (max_latency, retrans_effort) = super::param::accept_params(setting, pkt_type);
        AcceptSyncConn {
            bdaddr,
            tx_bandwidth: u::SCO_BANDWIDTH,
            rx_bandwidth: u::SCO_BANDWIDTH,
            max_latency,
            content_format: setting,
            retrans_effort,
            pkt_type,
        }
    }

    /// Encode the parameters. # C: O(1)
    pub fn to_wire(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(u::ACCEPT_SYNC_CONN_LEN);
        v.extend_from_slice(self.bdaddr.as_bytes());
        v.extend_from_slice(&self.tx_bandwidth.to_le_bytes());
        v.extend_from_slice(&self.rx_bandwidth.to_le_bytes());
        v.extend_from_slice(&self.max_latency.to_le_bytes());
        v.extend_from_slice(&self.content_format.to_le_bytes());
        v.push(self.retrans_effort);
        v.extend_from_slice(&self.pkt_type.to_le_bytes());
        v
    }

    /// Decode the parameters. # C: O(1)
    pub fn from_wire(b: &[u8]) -> Option<AcceptSyncConn> {
        if b.len() < u::ACCEPT_SYNC_CONN_LEN { return None; }
        Some(AcceptSyncConn {
            bdaddr: BdAddr::from_wire(b, 0)?,
            tx_bandwidth: u32::from_le_bytes([b[6], b[7], b[8], b[9]]),
            rx_bandwidth: u32::from_le_bytes([b[10], b[11], b[12], b[13]]),
            max_latency: u16::from_le_bytes([b[14], b[15]]),
            content_format: u16::from_le_bytes([b[16], b[17]]),
            retrans_effort: b[18],
            pkt_type: u16::from_le_bytes([b[19], b[20]]),
        })
    }
}
