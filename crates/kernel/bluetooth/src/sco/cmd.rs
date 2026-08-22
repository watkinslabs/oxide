//! Synchronous-connection setup and accept commands.
//!
//! Both carry the same negotiated quantities under different names — the
//! outgoing command names the voice setting, the accept names the content
//! format — and both ask for the same bandwidth in each direction.

use alloc::vec::Vec;

use crate::uapi::bt::BdAddr;
use crate::uapi::sco::{self as u, BtCodec, BT_CODEC_CVSD, BT_CODEC_MSBC,
                       BT_CODEC_TRANSPARENT};
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

/// Five-byte HCI coding-format descriptor.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CodingFormat { pub id: u8, pub cid: u16, pub vid: u16 }

impl CodingFormat {
    fn codec(codec: BtCodec) -> CodingFormat {
        CodingFormat { id: codec.id, cid: codec.cid, vid: codec.vid }
    }

    fn pcm(id: u8) -> CodingFormat { CodingFormat { id, cid: 0, vid: 0 } }

    fn append(&self, wire: &mut Vec<u8>) {
        wire.push(self.id);
        wire.extend_from_slice(&self.cid.to_le_bytes());
        wire.extend_from_slice(&self.vid.to_le_bytes());
    }
}

/// `HCI_OP_ENHANCED_SETUP_SYNC_CONN` parameters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EnhancedSetupSyncConn {
    pub handle: u16,
    pub tx_bandwidth: u32,
    pub rx_bandwidth: u32,
    pub tx_coding_format: CodingFormat,
    pub rx_coding_format: CodingFormat,
    pub tx_codec_frame_size: u16,
    pub rx_codec_frame_size: u16,
    pub in_bandwidth: u32,
    pub out_bandwidth: u32,
    pub in_coding_format: CodingFormat,
    pub out_coding_format: CodingFormat,
    pub in_coded_data_size: u16,
    pub out_coded_data_size: u16,
    pub in_pcm_data_format: u8,
    pub out_pcm_data_format: u8,
    pub in_pcm_sample_payload_msb_pos: u8,
    pub out_pcm_sample_payload_msb_pos: u8,
    pub in_data_path: u8,
    pub out_data_path: u8,
    pub in_transport_unit_size: u8,
    pub out_transport_unit_size: u8,
    pub max_latency: u16,
    pub pkt_type: u16,
    pub retrans_effort: u8,
}

impl EnhancedSetupSyncConn {
    /// Build the enhanced command's codec and transport contract. # C: O(1)
    pub fn new(handle: u16, codec: BtCodec, param: &ScoParam) -> Option<Self> {
        let (pcm_bandwidth, pcm_format, transport_unit) = match codec.id {
            BT_CODEC_MSBC => (u::SCO_MSBC_PCM_BANDWIDTH, u::HCI_CODING_FORMAT_PCM,
                              u::SCO_TRANSPORT_UNIT_CODEC),
            BT_CODEC_TRANSPARENT => (u::SCO_BANDWIDTH, BT_CODEC_TRANSPARENT,
                                     u::SCO_TRANSPORT_UNIT_CODEC),
            BT_CODEC_CVSD => (u::SCO_CVSD_PCM_BANDWIDTH, u::HCI_CODING_FORMAT_PCM,
                              u::SCO_TRANSPORT_UNIT_CVSD),
            _ => return None,
        };
        Some(Self {
            handle, tx_bandwidth: u::SCO_BANDWIDTH, rx_bandwidth: u::SCO_BANDWIDTH,
            tx_coding_format: CodingFormat::codec(codec),
            rx_coding_format: CodingFormat::codec(codec),
            tx_codec_frame_size: u::SCO_CODEC_FRAME_SIZE,
            rx_codec_frame_size: u::SCO_CODEC_FRAME_SIZE,
            in_bandwidth: pcm_bandwidth, out_bandwidth: pcm_bandwidth,
            in_coding_format: CodingFormat::pcm(pcm_format),
            out_coding_format: CodingFormat::pcm(pcm_format),
            in_coded_data_size: u::SCO_CODED_DATA_SIZE,
            out_coded_data_size: u::SCO_CODED_DATA_SIZE,
            in_pcm_data_format: u::HCI_PCM_DATA_FORMAT_TWOS_COMPLEMENT,
            out_pcm_data_format: u::HCI_PCM_DATA_FORMAT_TWOS_COMPLEMENT,
            in_pcm_sample_payload_msb_pos: 0, out_pcm_sample_payload_msb_pos: 0,
            in_data_path: codec.data_path, out_data_path: codec.data_path,
            in_transport_unit_size: transport_unit, out_transport_unit_size: transport_unit,
            max_latency: param.max_latency, pkt_type: param.pkt_type,
            retrans_effort: param.retrans_effort,
        })
    }

    /// Encode all 59 bytes in controller wire order. # C: O(1)
    pub fn to_wire(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(u::ENHANCED_SETUP_SYNC_CONN_LEN);
        v.extend_from_slice(&self.handle.to_le_bytes());
        v.extend_from_slice(&self.tx_bandwidth.to_le_bytes());
        v.extend_from_slice(&self.rx_bandwidth.to_le_bytes());
        self.tx_coding_format.append(&mut v);
        self.rx_coding_format.append(&mut v);
        v.extend_from_slice(&self.tx_codec_frame_size.to_le_bytes());
        v.extend_from_slice(&self.rx_codec_frame_size.to_le_bytes());
        v.extend_from_slice(&self.in_bandwidth.to_le_bytes());
        v.extend_from_slice(&self.out_bandwidth.to_le_bytes());
        self.in_coding_format.append(&mut v);
        self.out_coding_format.append(&mut v);
        v.extend_from_slice(&self.in_coded_data_size.to_le_bytes());
        v.extend_from_slice(&self.out_coded_data_size.to_le_bytes());
        v.extend_from_slice(&[self.in_pcm_data_format, self.out_pcm_data_format,
            self.in_pcm_sample_payload_msb_pos, self.out_pcm_sample_payload_msb_pos,
            self.in_data_path, self.out_data_path, self.in_transport_unit_size,
            self.out_transport_unit_size]);
        v.extend_from_slice(&self.max_latency.to_le_bytes());
        v.extend_from_slice(&self.pkt_type.to_le_bytes());
        v.push(self.retrans_effort);
        v
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
