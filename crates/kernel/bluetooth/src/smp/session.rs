//! Per-link pairing state.
//!
//! The session is transport-free: it consumes decoded frames and produces a
//! list of things to do — frames to send, users to ask, keys to store,
//! encryption to start. Keeping it that way is what lets the whole protocol be
//! driven from a test without a controller.
//!
//! Randomness is a parameter of every step that needs it rather than something
//! the session reaches for. A pairing whose nonces come from an argument can
//! be replayed exactly, which is the only way the published vectors can be
//! checked end to end.

extern crate alloc;
use alloc::vec::Vec;

use p256::SecretKey;

use crate::hci::conn::PeerId;
use crate::uapi::bt::{BT_SECURITY_LOW, BdAddr};
use crate::uapi::smp::*;
use super::keys::{Csrk, Irk, LinkKey, Ltk};
use super::method::JUST_WORKS;
use super::pdu::{PairingCmd, Pdu};

/// What this host is and what it is willing to do.
#[derive(Copy, Clone, Debug)]
pub struct SmpConfig {
    pub io_capability: u8,
    /// Whether this host published out-of-band data the peer may have read.
    pub local_oob: bool,
    /// Whether this host holds out-of-band data for the peer.
    pub peer_oob: bool,
    pub sc_enabled: bool,
    /// Whether a key for the other transport is derived and distributed.
    pub cross_transport: bool,
    pub bondable: bool,
    /// Whether this host distributes an identity resolving key.
    pub privacy: bool,
    /// Whether this host wants the peer's identity resolving key.
    pub rpa_resolving: bool,
    /// Largest encryption key the controller supports.
    pub max_key_size: u8,
}

impl Default for SmpConfig {
    fn default() -> SmpConfig {
        SmpConfig {
            io_capability: SMP_IO_NO_INPUT_OUTPUT,
            local_oob: false,
            peer_oob: false,
            sc_enabled: true,
            cross_transport: true,
            bondable: true,
            privacy: false,
            rpa_resolving: false,
            max_key_size: SMP_MAX_ENC_KEY_SIZE,
        }
    }
}

/// The two link addresses in the roles the crypto functions name them by.
#[derive(Copy, Clone, Debug)]
pub struct LinkAddrs {
    pub init_addr: BdAddr,
    pub init_addr_type: u8,
    pub resp_addr: BdAddr,
    pub resp_addr_type: u8,
}

impl LinkAddrs {
    /// The initiator address in the seven-byte form the derivation takes.
    /// # C: O(1)
    pub fn a1(&self) -> [u8; SMP_ADDR_LEN] { pack_addr(&self.init_addr, self.init_addr_type) }

    /// The responder address in the same form. # C: O(1)
    pub fn a2(&self) -> [u8; SMP_ADDR_LEN] { pack_addr(&self.resp_addr, self.resp_addr_type) }
}

/// Address bytes followed by the address type. # C: O(1)
pub fn pack_addr(addr: &BdAddr, addr_type: u8) -> [u8; SMP_ADDR_LEN] {
    let mut a = [0u8; SMP_ADDR_LEN];
    a[..addr.as_bytes().len()].copy_from_slice(addr.as_bytes());
    a[SMP_ADDR_LEN - 1] = addr_type;
    a
}

/// Randomness a step needs, supplied by the caller.
#[derive(Copy, Clone, Debug, Default)]
pub struct Entropy {
    /// Nonce for this step's confirm or random exchange.
    pub nonce: [u8; SMP_RAND_LEN],
    /// Passkey to display, before reduction to six digits.
    pub passkey: u32,
    /// Key material for a distributed long-term key.
    pub ltk: [u8; SMP_KEY_LEN],
    pub ediv: u16,
    pub rand: u64,
}

/// Something the session wants done.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SmpEvent {
    /// Send this frame to the peer.
    Send(Pdu),
    /// Abandon the pairing with this reason, which is also sent.
    Fail(u8),
    /// Ask the user to confirm. `hint` marks the case where there is no number
    /// to compare and the answer is only an acknowledgement.
    UserConfirm { passkey: u32, hint: bool },
    /// Ask the user for the passkey the peer is displaying.
    UserPasskeyRequest,
    /// Show the user a passkey to type on the peer.
    UserPasskeyNotify(u32),
    /// Start link encryption with this key.
    StartEncryption { ltk: [u8; SMP_KEY_LEN], ediv: u16, rand: u64, key_size: u8 },
    StoreLtk(Ltk),
    StoreIrk(Irk),
    StoreCsrk(Csrk),
    StoreLinkKey(LinkKey),
    /// Distribute the local identity address alongside the resolving key.
    SendIdentAddr,
    /// Pairing finished successfully.
    Complete,
}

/// One pairing attempt.
pub struct Smp {
    pub cfg: SmpConfig,
    pub peer: PeerId,
    pub addrs: LinkAddrs,
    /// Whether this host sent the pairing request.
    pub initiator: bool,
    /// Whether the exchange is a secure-connections one.
    pub sc: bool,
    /// Whether both sides offered the second-generation derivation.
    pub ct2: bool,
    pub method: u8,
    /// The pairing request frame, code byte included, as the confirm needs it.
    pub preq: [u8; SMP_PAIRING_PDU_LEN],
    /// The pairing response frame, likewise.
    pub prsp: [u8; SMP_PAIRING_PDU_LEN],
    /// Temporary key in legacy pairing; the long-term key once derived.
    pub tk: [u8; SMP_KEY_LEN],
    pub prnd: [u8; SMP_RAND_LEN],
    pub rrnd: [u8; SMP_RAND_LEN],
    /// Confirm value received from the peer.
    pub pcnf: [u8; SMP_KEY_LEN],
    pub enc_key_size: u8,
    pub passkey: u32,
    pub passkey_round: u8,
    pub local_pk: [u8; SMP_PUBLIC_KEY_LEN],
    pub remote_pk: [u8; SMP_PUBLIC_KEY_LEN],
    pub dhkey: [u8; SMP_DHKEY_LEN],
    pub mackey: [u8; SMP_KEY_LEN],
    /// Out-of-band random value received from the peer.
    pub rr: [u8; SMP_RAND_LEN],
    /// Out-of-band random value this host published.
    pub lr: [u8; SMP_RAND_LEN],
    pub remote_oob: bool,
    pub local_oob: bool,
    pub debug_key: bool,
    pub remote_key_dist: u8,
    pub local_key_dist: u8,
    /// Codes the peer may send next, one bit per code.
    pub allowed: u32,
    /// Level this pairing is expected to reach.
    pub pending_sec_level: u8,
    /// Deadline in the caller's millisecond clock.
    pub deadline_ms: u64,
    /// Whether a user answer is outstanding.
    pub wait_user: bool,
    /// Whether a confirm arrived while a user answer was outstanding.
    pub cfm_pending: bool,
    /// Whether a check arrived while a user answer was outstanding.
    pub dhkey_pending: bool,
    /// This host's private key for a secure-connections exchange.
    pub local_sk: Option<SecretKey>,
}

/// Requirement bits that may appear on the wire. Reserved bits are cleared so
/// a peer cannot make this host believe it negotiated something it did not.
/// # C: O(1)
pub fn auth_req_mask(sc_enabled: bool) -> u8 {
    if sc_enabled {
        SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC | SMP_AUTH_KEYPRESS | SMP_AUTH_CT2 | 0x02
    } else {
        SMP_AUTH_BONDING | SMP_AUTH_MITM | 0x02
    }
}

impl Smp {
    /// A session for a link, with nothing negotiated yet. # C: O(1)
    pub fn new(cfg: SmpConfig, peer: PeerId, addrs: LinkAddrs, now_ms: u64) -> Smp {
        Smp {
            cfg, peer, addrs,
            initiator: false, sc: false, ct2: false, method: JUST_WORKS,
            preq: [0; SMP_PAIRING_PDU_LEN], prsp: [0; SMP_PAIRING_PDU_LEN],
            tk: [0; SMP_KEY_LEN], prnd: [0; SMP_RAND_LEN], rrnd: [0; SMP_RAND_LEN],
            pcnf: [0; SMP_KEY_LEN], enc_key_size: cfg.max_key_size,
            passkey: 0, passkey_round: 0,
            local_pk: [0; SMP_PUBLIC_KEY_LEN], remote_pk: [0; SMP_PUBLIC_KEY_LEN],
            dhkey: [0; SMP_DHKEY_LEN], mackey: [0; SMP_KEY_LEN],
            rr: [0; SMP_RAND_LEN], lr: [0; SMP_RAND_LEN],
            remote_oob: false, local_oob: false, debug_key: false,
            remote_key_dist: 0, local_key_dist: 0,
            allowed: 0, pending_sec_level: BT_SECURITY_LOW,
            deadline_ms: now_ms + SMP_TIMEOUT_MS,
            wait_user: false, cfm_pending: false, dhkey_pending: false,
            local_sk: None,
        }
    }

    /// Restart the stall deadline, which every received frame does. # C: O(1)
    pub fn touch(&mut self, now_ms: u64) { self.deadline_ms = now_ms + SMP_TIMEOUT_MS; }

    /// Whether the pairing has stalled past its deadline. # C: O(1)
    pub fn expired(&self, now_ms: u64) -> bool { now_ms >= self.deadline_ms }

    /// Permit exactly one code from the peer, which is how a frame arriving
    /// out of order is refused rather than acted on. # C: O(1)
    pub fn allow(&mut self, code: u8) { self.allowed |= 1u32 << code; }

    /// Permit an additional code without clearing the others. # C: O(1)
    pub fn allow_only(&mut self, code: u8) { self.allowed = 1u32 << code; }

    /// Consume the permission for a code, reporting whether it was there.
    /// # C: O(1)
    pub fn take_allowed(&mut self, code: u8) -> bool {
        let bit = 1u32 << code;
        let had = self.allowed & bit != 0;
        self.allowed &= !bit;
        had
    }

    /// Build the local half of a pairing exchange. # C: O(1)
    pub fn build_pairing_cmd(&mut self, mut authreq: u8, peer_req: Option<&PairingCmd>) -> PairingCmd {
        let mut local_dist = 0u8;
        let mut remote_dist = 0u8;
        if self.cfg.bondable {
            local_dist = SMP_DIST_ENC_KEY | SMP_DIST_SIGN;
            remote_dist = SMP_DIST_ENC_KEY | SMP_DIST_SIGN;
            authreq |= SMP_AUTH_BONDING;
        } else {
            authreq &= !SMP_AUTH_BONDING;
        }
        if self.cfg.rpa_resolving { remote_dist |= SMP_DIST_ID_KEY; }
        if self.cfg.privacy { local_dist |= SMP_DIST_ID_KEY; }

        let mut oob_flag = SMP_OOB_NOT_PRESENT;
        if self.cfg.sc_enabled && authreq & SMP_AUTH_SC != 0 {
            if self.cfg.cross_transport {
                local_dist |= SMP_DIST_LINK_KEY;
                remote_dist |= SMP_DIST_LINK_KEY;
            }
            if self.cfg.peer_oob {
                oob_flag = SMP_OOB_PRESENT;
                self.remote_oob = true;
            }
        } else {
            authreq &= !SMP_AUTH_SC;
        }
        authreq &= auth_req_mask(self.cfg.sc_enabled);

        match peer_req {
            None => {
                self.remote_key_dist = remote_dist;
                self.local_key_dist = local_dist;
                PairingCmd {
                    io_capability: self.cfg.io_capability,
                    oob_flag,
                    auth_req: authreq,
                    max_key_size: self.cfg.max_key_size,
                    init_key_dist: local_dist,
                    resp_key_dist: remote_dist,
                }
            }
            Some(req) => {
                let rsp = PairingCmd {
                    io_capability: self.cfg.io_capability,
                    oob_flag,
                    auth_req: authreq,
                    max_key_size: self.cfg.max_key_size,
                    init_key_dist: req.init_key_dist & remote_dist,
                    resp_key_dist: req.resp_key_dist & local_dist,
                };
                self.remote_key_dist = rsp.init_key_dist;
                self.local_key_dist = rsp.resp_key_dist;
                rsp
            }
        }
    }

    /// Record the pairing request frame the confirm value consumes. # C: O(1)
    pub fn set_preq(&mut self, cmd: &PairingCmd) {
        self.preq[0] = SMP_CMD_PAIRING_REQ;
        self.preq[1..].copy_from_slice(&cmd.to_bytes());
    }

    /// Record the pairing response frame likewise. # C: O(1)
    pub fn set_prsp(&mut self, cmd: &PairingCmd) {
        self.prsp[0] = SMP_CMD_PAIRING_RSP;
        self.prsp[1..].copy_from_slice(&cmd.to_bytes());
    }

    /// The pairing request body as decoded. # C: O(1)
    pub fn req(&self) -> PairingCmd {
        PairingCmd::from_bytes(self.preq[SMP_CODE_LEN..].try_into().unwrap())
    }

    /// The pairing response body as decoded. # C: O(1)
    pub fn rsp(&self) -> PairingCmd {
        PairingCmd::from_bytes(self.prsp[SMP_CODE_LEN..].try_into().unwrap())
    }

    /// The three capability bytes of whichever frame this host sent, which is
    /// what its own check value is computed over. # C: O(1)
    pub fn local_io_cap(&self) -> [u8; SMP_IO_CAP_LEN] {
        let src = if self.initiator { &self.preq } else { &self.prsp };
        [src[1], src[2], src[3]]
    }

    /// The peer's three capability bytes, which its check value used.
    /// # C: O(1)
    pub fn remote_io_cap(&self) -> [u8; SMP_IO_CAP_LEN] {
        let src = if self.initiator { &self.prsp } else { &self.preq };
        [src[1], src[2], src[3]]
    }

    /// The local and remote addresses in the order this host's own derivation
    /// takes them. # C: O(1)
    pub fn local_remote_addrs(&self) -> ([u8; SMP_ADDR_LEN], [u8; SMP_ADDR_LEN]) {
        if self.initiator { (self.addrs.a1(), self.addrs.a2()) }
        else { (self.addrs.a2(), self.addrs.a1()) }
    }

    /// The nonces in initiator-then-responder order, which the key derivation
    /// requires regardless of which side is computing it. # C: O(1)
    pub fn ordered_nonces(&self) -> ([u8; SMP_RAND_LEN], [u8; SMP_RAND_LEN]) {
        if self.initiator { (self.prnd, self.rrnd) } else { (self.rrnd, self.prnd) }
    }

    /// The public key x coordinates in initiator-then-responder order.
    /// # C: O(1)
    pub fn ordered_pk_x(&self) -> ([u8; SMP_PUBKEY_COORD_LEN], [u8; SMP_PUBKEY_COORD_LEN]) {
        let local = coord_x(&self.local_pk);
        let remote = coord_x(&self.remote_pk);
        if self.initiator { (local, remote) } else { (remote, local) }
    }
}

/// The x coordinate half of a public key. # C: O(1)
pub fn coord_x(pk: &[u8; SMP_PUBLIC_KEY_LEN]) -> [u8; SMP_PUBKEY_COORD_LEN] {
    let mut x = [0u8; SMP_PUBKEY_COORD_LEN];
    x.copy_from_slice(&pk[..SMP_PUBKEY_COORD_LEN]);
    x
}

/// The y coordinate half. # C: O(1)
pub fn coord_y(pk: &[u8; SMP_PUBLIC_KEY_LEN]) -> [u8; SMP_PUBKEY_COORD_LEN] {
    let mut y = [0u8; SMP_PUBKEY_COORD_LEN];
    y.copy_from_slice(&pk[SMP_PUBKEY_COORD_LEN..]);
    y
}

/// Collect events; the entry points append rather than return so a step that
/// produces several does not allocate a list per step. # C: O(1)
pub type Events = Vec<SmpEvent>;
