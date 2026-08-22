//! A synchronous link and its negotiation.
//!
//! One link walks the parameter table from the top: each refusal the controller
//! reports for a reason that a weaker parameter set could fix advances the
//! attempt and asks again. A refusal for any other reason, and running off the
//! end of the table, close the link instead — retrying forever on a permanent
//! error is how a headset connect turns into a loop.

use crate::uapi::bt::{BdAddr, BT_CLOSED, BT_CONFIG, BT_CONNECT, BT_CONNECTED, BT_OPEN,
                      BT_VOICE_CVSD_16BIT};
use crate::uapi::hci_cmd::{HCI_OP_ACCEPT_SYNC_CONN_REQ, HCI_OP_ENHANCED_SETUP_SYNC_CONN,
                           HCI_OP_SETUP_SYNC_CONN};
use crate::uapi::sco::{BtCodec, SyncConnComplete, BT_CODEC_CVSD, BT_CODEC_TRANSPARENT,
                       SCO_DEFAULT_MTU};
use crate::uapi::hci::{ESCO_LINK, SCO_AIRMODE_MASK, SCO_AIRMODE_TRANSP, SCO_ESCO_MASK,
                       EDR_ESCO_MASK};
use super::cmd::{AcceptSyncConn, EnhancedSetupSyncConn, SetupSyncConn};
use super::link::ScoTx;
use super::param::{self, LinkCaps, ParamError};

/// Controller statuses that a weaker parameter set might get past. Any other
/// refusal is permanent for this link.
pub const RETRYABLE_STATUS: [u8; 8] = [0x10, 0x0d, 0x11, 0x1c, 0x1a, 0x1e, 0x1f, 0x20];

/// Whether a refusal is worth another attempt. # C: O(1)
pub fn retryable(status: u8) -> bool { RETRYABLE_STATUS.contains(&status) }

/// One synchronous link.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SyncLink {
    pub handle: u16,
    pub peer: BdAddr,
    /// Voice setting, whose air-coding field chooses the parameter table.
    pub setting: u16,
    pub codec: BtCodec,
    /// One-based row of the parameter table the next attempt will use, after
    /// it has been advanced.
    pub attempt: u16,
    pub state: u8,
    pub caps: LinkCaps,
    /// Packet types the controller offers, used when answering an inbound
    /// request.
    pub pkt_type: u16,
    /// Payload ceiling, replaced by what the controller reports once the link
    /// is up.
    pub mtu: u16,
    pub link_type: u8,
    /// Whether this host initiated the link.
    pub out: bool,
}

/// What a completion event means for a link.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    Connected,
    /// Another attempt was made; the command is already on its way.
    Retried,
    /// The link is closed, carrying the controller's status.
    Failed(u8),
}

impl SyncLink {
    /// A link about to be set up, before any attempt. # C: O(1)
    pub fn new(peer: BdAddr, setting: u16, caps: LinkCaps) -> SyncLink {
        SyncLink {
            handle: 0,
            peer,
            setting,
            codec: default_codec(setting),
            attempt: 0,
            state: BT_OPEN,
            caps,
            pkt_type: (SCO_ESCO_MASK | EDR_ESCO_MASK),
            mtu: SCO_DEFAULT_MTU,
            link_type: ESCO_LINK,
            out: false,
        }
    }

    /// Make one attempt at setting the link up over the baseband link named by
    /// `acl_handle`. Advances the attempt counter first, so a retry never
    /// repeats the parameters that were just refused. # C: O(n)
    pub fn setup<T: ScoTx>(&mut self, acl_handle: u16, tx: &mut T) -> Result<SetupSyncConn, ParamError> {
        self.attempt += 1;
        let (attempt, param) = param::select(self.setting, self.attempt, self.caps)?;
        self.attempt = attempt;
        self.state = BT_CONNECT;
        self.out = true;
        let cp = SetupSyncConn::new(acl_handle, self.setting, &param);
        if self.caps.enhanced_setup {
            let enhanced = EnhancedSetupSyncConn::new(acl_handle, self.codec, &param)
                .ok_or(ParamError::BadAirMode)?;
            let _ = tx.send_cmd(HCI_OP_ENHANCED_SETUP_SYNC_CONN, &enhanced.to_wire());
        } else {
            let _ = tx.send_cmd(HCI_OP_SETUP_SYNC_CONN, &cp.to_wire());
        }
        Ok(cp)
    }

    /// Answer an inbound request, which is what a deferred accept does once
    /// userspace has decided. # C: O(1)
    pub fn accept<T: ScoTx>(&mut self, tx: &mut T) -> AcceptSyncConn {
        self.state = BT_CONFIG;
        let cp = AcceptSyncConn::new(self.peer, self.setting, self.pkt_type);
        let _ = tx.send_cmd(HCI_OP_ACCEPT_SYNC_CONN_REQ, &cp.to_wire());
        cp
    }

    /// Act on a completion event: adopt what the controller reports, or make the
    /// next attempt, or close. Only an outgoing link retries — an inbound one
    /// has no table left to walk. # C: O(n)
    pub fn on_complete<T: ScoTx>(&mut self, ev: &SyncConnComplete, acl_handle: u16, tx: &mut T) -> Outcome {
        if ev.status == 0 {
            self.handle = ev.handle;
            self.link_type = ev.link_type;
            self.state = BT_CONNECTED;
            if ev.tx_pkt_len != 0 { self.mtu = ev.tx_pkt_len; }
            return Outcome::Connected;
        }
        if self.out && retryable(ev.status) && self.setup(acl_handle, tx).is_ok() {
            return Outcome::Retried;
        }
        self.state = BT_CLOSED;
        Outcome::Failed(ev.status)
    }
}

/// The codec a voice setting implies before any explicit selection: transparent
/// air coding carries a transparent codec, anything else the variable-slope one.
/// # C: O(1)
pub fn default_codec(setting: u16) -> BtCodec {
    let id = if setting & SCO_AIRMODE_MASK == SCO_AIRMODE_TRANSP { BT_CODEC_TRANSPARENT } else { BT_CODEC_CVSD };
    BtCodec { id, cid: 0, vid: 0, data_path: 0, num_caps: 0 }
}

/// The voice setting a socket starts with. # C: O(1)
pub fn default_setting() -> u16 { BT_VOICE_CVSD_16BIT }
