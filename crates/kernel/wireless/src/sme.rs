// The station management entity: what happens between `CONNECT` and a link
// that carries traffic, and what happens when it comes apart.
//
// The software state machine here runs the sequence a client needs — find the
// network, authenticate, associate, report the result — and it is a state
// machine rather than a sequence of calls because every step can time out,
// every step can be pre-empted by a local disconnect, and the frame that ends
// a step can arrive after the step gave up. The invariant the tests pin is
// that exactly one terminal event reaches userspace per connect attempt: a
// connect result or a disconnect, never both and never neither.

extern crate alloc;

use alloc::vec::Vec;

use crate::ieee80211::status::status;
use crate::ieee80211::MacAddr;
use crate::uapi::enums::{auth_type, timeout_reason};

/// Sub-state of a connect attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConnStep {
    /// Looking for the network.
    #[default]
    Scanning,
    /// The scan found nothing usable; one more scan is allowed.
    ScanAgain,
    /// Ready to send an authenticate.
    AuthenticateNext,
    /// Authenticate sent, waiting for the response.
    Authenticating,
    /// Authentication timed out.
    AuthFailedTimeout,
    /// Ready to send an associate.
    AssociateNext,
    /// Associate sent, waiting for the response.
    Associating,
    /// Association was refused.
    AssocFailed,
    /// Association timed out.
    AssocFailedTimeout,
    /// Tearing the attempt down with a deauthenticate.
    Deauth,
    /// Giving up without sending anything further.
    Abandon,
    /// Associated.
    Connected,
}

/// What userspace asked for in a `CONNECT`.
#[derive(Clone, Debug, Default)]
pub struct ConnectParams {
    pub ssid: Vec<u8>,
    /// BSSID the request pins, if it pinned one.
    pub bssid: Option<MacAddr>,
    /// BSSID the request suggests but does not require.
    pub bssid_hint: Option<MacAddr>,
    /// Frequency in MHz the request pins, if it pinned one.
    pub freq: Option<u32>,
    pub freq_hint: Option<u32>,
    pub auth_type: u32,
    pub privacy: bool,
    pub wpa_versions: u32,
    pub cipher_group: Option<u32>,
    pub ciphers_pairwise: Vec<u32>,
    pub akm_suites: Vec<u32>,
    pub ie: Vec<u8>,
    pub mfp: u32,
    /// Previous BSSID, for a reassociation.
    pub prev_bssid: Option<MacAddr>,
    /// Whether the four-way handshake runs in userspace, so the port stays
    /// unauthorized until userspace says otherwise.
    pub want_1x: bool,
    /// The kernel picks the authentication algorithm and retries the other on
    /// refusal.
    pub auto_auth: bool,
}

/// Live connection state of one interface.
#[derive(Clone, Debug, Default)]
pub struct ConnState {
    /// Attempt in progress, if any.
    pub conn: Option<Conn>,
    /// BSSID of the current association.
    pub current_bssid: Option<MacAddr>,
    /// Whether the association has completed.
    pub connected: bool,
    /// Whether the controlled port is open, so data frames may flow.
    pub port_authorized: bool,
    /// Association identifier the AP handed out.
    pub aid: u16,
    /// Association request and response elements, as reported to userspace.
    pub req_ie: Vec<u8>,
    pub resp_ie: Vec<u8>,
    /// Peers this interface has authenticated with but not associated to.
    pub authenticated: Vec<MacAddr>,
}

/// One connect attempt.
#[derive(Clone, Debug)]
pub struct Conn {
    pub params: ConnectParams,
    pub step: ConnStep,
    pub bssid: MacAddr,
    pub prev_bssid: Option<MacAddr>,
    /// Authentication algorithm currently being tried.
    pub auth_alg: u16,
    /// Scans already run for this attempt.
    pub scans: u32,
}

/// The single terminal outcome of a connect attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectResult {
    /// Associated. Carries the identifier and the two element blobs.
    Success { bssid: MacAddr, aid: u16 },
    /// Refused by the network, with the status code it sent.
    Refused { bssid: Option<MacAddr>, status: u16 },
    /// Gave up locally, with the step that ran out of time.
    TimedOut { reason: u32 },
}

/// What the state machine wants done next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnAction {
    /// Run a scan for the network.
    Scan,
    /// Send an authenticate to this peer with this algorithm.
    Authenticate { bssid: MacAddr, alg: u16 },
    /// Send an associate to this peer.
    Associate { bssid: MacAddr },
    /// Send a deauthenticate with this reason.
    Deauthenticate { bssid: MacAddr, reason: u16 },
    /// Report the outcome to userspace and drop the attempt.
    Report(ConnectResult),
    /// Nothing to do.
    None,
}

/// Number of scans a connect attempt may run before giving up.
pub const MAX_CONN_SCANS: u32 = 2;

/// Authentication algorithm an authentication type asks for. An automatic
/// request starts with the open algorithm, which every network accepts, and
/// falls back only if that is refused. # C: O(1)
pub fn alg_for_auth_type(ty: u32) -> u16 {
    use crate::ieee80211::mgmt::auth_alg;
    match ty {
        auth_type::SHARED_KEY => auth_alg::SHARED_KEY,
        auth_type::FT => auth_alg::FT,
        auth_type::NETWORK_EAP => auth_alg::NETWORK_EAP,
        auth_type::SAE => auth_alg::SAE,
        auth_type::FILS_SK => auth_alg::FILS_SK,
        auth_type::FILS_SK_PFS => auth_alg::FILS_SK_PFS,
        auth_type::FILS_PK => auth_alg::FILS_PK,
        _ => auth_alg::OPEN,
    }
}

impl Conn {
    /// Start an attempt. # C: O(1)
    pub fn new(params: ConnectParams) -> Self {
        let bssid = params.bssid.or(params.bssid_hint).unwrap_or(MacAddr::ZERO);
        let auto_auth = params.auth_type == auth_type::AUTOMATIC;
        let auth_alg = alg_for_auth_type(params.auth_type);
        let prev_bssid = params.prev_bssid;
        // A request that already names a BSS does not need a scan to find it,
        // but it still needs the BSS entry the scan cache holds, so the first
        // step is a scan either way.
        Self { params: ConnectParams { auto_auth, ..params }, step: ConnStep::Scanning,
               bssid, prev_bssid, auth_alg, scans: 0 }
    }

    /// What to do in the current step. # C: O(1)
    pub fn action(&self) -> ConnAction {
        match self.step {
            ConnStep::Scanning | ConnStep::ScanAgain => ConnAction::Scan,
            ConnStep::AuthenticateNext =>
                ConnAction::Authenticate { bssid: self.bssid, alg: self.auth_alg },
            ConnStep::AssociateNext => ConnAction::Associate { bssid: self.bssid },
            ConnStep::Deauth => ConnAction::Deauthenticate {
                bssid: self.bssid,
                reason: crate::ieee80211::status::reason::DEAUTH_LEAVING,
            },
            ConnStep::AuthFailedTimeout => ConnAction::Report(ConnectResult::TimedOut {
                reason: timeout_reason::AUTH }),
            ConnStep::AssocFailedTimeout => ConnAction::Report(ConnectResult::TimedOut {
                reason: timeout_reason::ASSOC }),
            ConnStep::AssocFailed => ConnAction::Report(ConnectResult::Refused {
                bssid: Some(self.bssid), status: status::UNSPECIFIED_FAILURE }),
            ConnStep::Abandon => ConnAction::Report(ConnectResult::TimedOut {
                reason: timeout_reason::UNSPECIFIED }),
            ConnStep::Connected | ConnStep::Authenticating
                | ConnStep::Associating => ConnAction::None,
        }
    }

    /// A scan finished and found the network at this address. # C: O(1)
    pub fn scan_found(&mut self, bssid: MacAddr) {
        self.bssid = bssid;
        self.step = ConnStep::AuthenticateNext;
    }

    /// A scan finished and did not find the network. One more scan is run;
    /// after that the attempt is abandoned rather than retried forever.
    /// # C: O(1)
    pub fn scan_missed(&mut self) {
        self.scans += 1;
        self.step = if self.scans < MAX_CONN_SCANS { ConnStep::ScanAgain }
                    else { ConnStep::Abandon };
    }

    /// An authenticate has gone out. # C: O(1)
    pub fn auth_sent(&mut self) { self.step = ConnStep::Authenticating; }
    /// An associate has gone out. # C: O(1)
    pub fn assoc_sent(&mut self) { self.step = ConnStep::Associating; }

    /// An authentication response arrived. A refusal of the open algorithm on
    /// an automatic request is retried with the shared-key algorithm exactly
    /// once, which is the whole reason the automatic type exists. # C: O(1)
    pub fn auth_response(&mut self, code: u16) {
        use crate::ieee80211::mgmt::auth_alg;
        if code == status::SUCCESS { self.step = ConnStep::AssociateNext; return; }
        if self.params.auto_auth && self.auth_alg == auth_alg::OPEN {
            self.auth_alg = auth_alg::SHARED_KEY;
            self.step = ConnStep::AuthenticateNext;
            return;
        }
        self.step = ConnStep::AssocFailed;
    }

    /// The authenticate timed out. # C: O(1)
    pub fn auth_timeout(&mut self) { self.step = ConnStep::AuthFailedTimeout; }

    /// An association response arrived. # C: O(1)
    pub fn assoc_response(&mut self, code: u16) {
        self.step = if code == status::SUCCESS { ConnStep::Connected }
                    else { ConnStep::AssocFailed };
    }

    /// The associate timed out. # C: O(1)
    pub fn assoc_timeout(&mut self) { self.step = ConnStep::AssocFailedTimeout; }

    /// A local disconnect arrived mid-attempt. Whether a deauthenticate goes
    /// out depends on how far the attempt got: there is nothing to
    /// deauthenticate from before the authentication exchange started.
    /// # C: O(1)
    pub fn local_disconnect(&mut self) {
        self.step = match self.step {
            ConnStep::Scanning | ConnStep::ScanAgain
                | ConnStep::AuthenticateNext => ConnStep::Abandon,
            _ => ConnStep::Deauth,
        };
    }

    /// Whether the attempt has reached a step that produces a terminal event.
    /// # C: O(1)
    pub fn is_terminal(&self) -> bool {
        matches!(self.step, ConnStep::Connected | ConnStep::AssocFailed
            | ConnStep::AuthFailedTimeout | ConnStep::AssocFailedTimeout
            | ConnStep::Abandon)
    }
}

impl ConnState {
    /// Whether a connect may be started. A second connect on an interface
    /// that is already connecting or connected is refused rather than
    /// silently replacing the first, because the first has a pending terminal
    /// event that userspace is waiting for. # C: O(1)
    pub fn can_connect(&self) -> bool { self.conn.is_none() && !self.connected }

    /// Record a completed association. # C: O(len)
    pub fn associated(&mut self, bssid: MacAddr, aid: u16, req_ie: Vec<u8>, resp_ie: Vec<u8>,
                      port_authorized: bool) {
        self.current_bssid = Some(bssid);
        self.connected = true;
        self.aid = aid;
        self.req_ie = req_ie;
        self.resp_ie = resp_ie;
        self.port_authorized = port_authorized;
        self.conn = None;
    }

    /// Record a disconnection. # C: O(1)
    pub fn disconnected(&mut self) {
        self.current_bssid = None;
        self.connected = false;
        self.port_authorized = false;
        self.aid = 0;
        self.req_ie.clear();
        self.resp_ie.clear();
        self.conn = None;
        self.authenticated.clear();
    }

    /// Record that this interface has authenticated with a peer. # C: O(N peers)
    pub fn note_authenticated(&mut self, peer: MacAddr) {
        if !self.authenticated.contains(&peer) { self.authenticated.push(peer); }
    }

    /// Whether this interface has authenticated with a peer. # C: O(N peers)
    pub fn is_authenticated(&self, peer: MacAddr) -> bool { self.authenticated.contains(&peer) }
}
