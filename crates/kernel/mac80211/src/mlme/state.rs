// The client-side management state machine.
//
// The invariant this file exists to hold is that EXACTLY ONE terminal outcome
// is produced per attempt. Every step can time out, every step can be
// pre-empted by a local disconnect, and the frame that ends a step can arrive
// after the step already gave up — so without an explicit record of whether a
// terminal outcome has been emitted, a late response after a timeout produces
// a second one, and userspace sees a connect that both failed and succeeded.

extern crate alloc;

use alloc::vec::Vec;

use wireless::ieee80211::status::status;
use wireless::ieee80211::MacAddr;
use wireless::uapi::enums::timeout_reason;

use crate::limits;

/// Where a client attempt has got to.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MlmeStep {
    /// No attempt in progress.
    #[default]
    Idle,
    /// An authenticate has gone out.
    Authenticating,
    /// The peer accepted the authentication.
    Authenticated,
    /// An associate has gone out.
    Associating,
    /// Associated.
    Associated,
}

/// What happened to the attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlmeEvent {
    /// An authentication response arrived with this status code.
    AuthResp(u16),
    /// The authenticate's deadline passed.
    AuthTimeout,
    /// An association response arrived with this status code and identifier.
    AssocResp { status: u16, aid: u16 },
    /// The associate's deadline passed.
    AssocTimeout,
    /// The peer ended the link.
    Deauth { reason: u16 },
    /// Userspace asked to stop.
    LocalDisconnect,
}

/// What the caller must do next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlmeAction {
    /// Nothing.
    None,
    /// Send an authenticate — a first attempt or a retry.
    SendAuth,
    /// Send an associate.
    SendAssoc,
    /// Send a deauthenticate with this reason, then report.
    SendDeauth { reason: u16 },
    /// The attempt succeeded. Reported once.
    Success { bssid: MacAddr, aid: u16 },
    /// The network refused. Reported once.
    Refused { status: u16 },
    /// The attempt ran out of time. Reported once.
    TimedOut { reason: u32 },
}

impl MlmeAction {
    /// Whether this action is the attempt's single terminal outcome.
    /// # C: O(1)
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Success { .. } | Self::Refused { .. } | Self::TimedOut { .. })
    }
}

/// The client state machine of one interface.
#[derive(Clone, Debug, Default)]
pub struct MlmeState {
    pub step: MlmeStep,
    /// Network being joined.
    pub bssid: Option<MacAddr>,
    pub ssid: Vec<u8>,
    /// Authentication algorithm in use.
    pub auth_alg: u16,
    /// Elements to send with the associate.
    pub assoc_ie: Vec<u8>,
    /// Elements the response carried, reported upward.
    pub resp_ie: Vec<u8>,
    pub auth_tries: u32,
    pub assoc_tries: u32,
    /// Monotonic nanoseconds the outstanding frame's response is due by.
    pub deadline_ns: u64,
    /// Beacons missed in a row while associated.
    pub beacons_missed: u32,
    /// Monotonic nanoseconds of the last beacon heard from the network.
    pub last_beacon_ns: u64,
    /// Association identifier the network handed out.
    pub aid: u16,
    /// Whether a terminal outcome has already been produced. This is the
    /// whole guard against reporting twice.
    pub reported: bool,
    /// Whether management frames on this link are protected.
    pub mfp: bool,
}

impl MlmeState {
    /// Begin an attempt against a network. # C: O(len)
    pub fn start(&mut self, bssid: MacAddr, ssid: Vec<u8>, auth_alg: u16, now_ns: u64)
        -> MlmeAction
    {
        *self = Self {
            step: MlmeStep::Idle, bssid: Some(bssid), ssid, auth_alg,
            deadline_ns: now_ns + limits::AUTH_TIMEOUT_NS, ..Default::default()
        };
        MlmeAction::SendAuth
    }

    /// Record that an authenticate has gone out. # C: O(1)
    pub fn auth_sent(&mut self, now_ns: u64) {
        self.step = MlmeStep::Authenticating;
        self.auth_tries += 1;
        self.deadline_ns = now_ns + limits::AUTH_TIMEOUT_NS;
    }

    /// Record that an associate has gone out. # C: O(1)
    pub fn assoc_sent(&mut self, now_ns: u64) {
        self.step = MlmeStep::Associating;
        self.assoc_tries += 1;
        self.deadline_ns = now_ns + limits::ASSOC_TIMEOUT_NS;
    }

    /// Whether the outstanding frame's deadline has passed. # C: O(1)
    pub fn expired(&self, now_ns: u64) -> bool {
        matches!(self.step, MlmeStep::Authenticating | MlmeStep::Associating)
            && now_ns >= self.deadline_ns
    }

    /// Take one event. # C: O(1)
    pub fn on_event(&mut self, ev: MlmeEvent, now_ns: u64) -> MlmeAction {
        match ev {
            MlmeEvent::AuthResp(code) => self.on_auth_resp(code),
            MlmeEvent::AuthTimeout => self.on_auth_timeout(now_ns),
            MlmeEvent::AssocResp { status, aid } => self.on_assoc_resp(status, aid),
            MlmeEvent::AssocTimeout => self.on_assoc_timeout(now_ns),
            MlmeEvent::Deauth { reason } => self.on_deauth(reason),
            MlmeEvent::LocalDisconnect => self.on_local_disconnect(),
        }
    }

    fn terminal(&mut self, action: MlmeAction) -> MlmeAction {
        if self.reported { return MlmeAction::None; }
        self.reported = true;
        action
    }

    fn on_auth_resp(&mut self, code: u16) -> MlmeAction {
        // A response that arrives when nothing is outstanding belongs to an
        // attempt already concluded and changes nothing.
        if self.step != MlmeStep::Authenticating { return MlmeAction::None; }
        if code != status::SUCCESS {
            self.step = MlmeStep::Idle;
            return self.terminal(MlmeAction::Refused { status: code });
        }
        self.step = MlmeStep::Authenticated;
        MlmeAction::SendAssoc
    }

    fn on_auth_timeout(&mut self, now_ns: u64) -> MlmeAction {
        if self.step != MlmeStep::Authenticating { return MlmeAction::None; }
        if self.auth_tries < limits::AUTH_MAX_TRIES {
            self.deadline_ns = now_ns + limits::AUTH_TIMEOUT_NS;
            return MlmeAction::SendAuth;
        }
        self.step = MlmeStep::Idle;
        self.terminal(MlmeAction::TimedOut { reason: timeout_reason::AUTH })
    }

    fn on_assoc_resp(&mut self, code: u16, aid: u16) -> MlmeAction {
        if self.step != MlmeStep::Associating { return MlmeAction::None; }
        if code != status::SUCCESS {
            self.step = MlmeStep::Authenticated;
            return self.terminal(MlmeAction::Refused { status: code });
        }
        self.step = MlmeStep::Associated;
        self.aid = aid;
        let bssid = self.bssid.unwrap_or(MacAddr::ZERO);
        self.terminal(MlmeAction::Success { bssid, aid })
    }

    fn on_assoc_timeout(&mut self, now_ns: u64) -> MlmeAction {
        if self.step != MlmeStep::Associating { return MlmeAction::None; }
        if self.assoc_tries < limits::ASSOC_MAX_TRIES {
            self.deadline_ns = now_ns + limits::ASSOC_TIMEOUT_NS;
            return MlmeAction::SendAssoc;
        }
        self.step = MlmeStep::Authenticated;
        self.terminal(MlmeAction::TimedOut { reason: timeout_reason::ASSOC })
    }

    fn on_deauth(&mut self, reason: u16) -> MlmeAction {
        let was_associated = self.step == MlmeStep::Associated;
        self.step = MlmeStep::Idle;
        if was_associated {
            // An established association ending is a disconnection, not the
            // outcome of an attempt, so it is reported however many outcomes
            // the earlier attempt produced.
            self.reported = true;
            return MlmeAction::Refused { status: reason };
        }
        self.terminal(MlmeAction::Refused { status: reason })
    }

    fn on_local_disconnect(&mut self) -> MlmeAction {
        let step = self.step;
        self.step = MlmeStep::Idle;
        match step {
            // Nothing has been said to the peer yet, so nothing needs saying.
            MlmeStep::Idle => self.terminal(MlmeAction::TimedOut {
                reason: timeout_reason::UNSPECIFIED }),
            _ => MlmeAction::SendDeauth {
                reason: wireless::ieee80211::status::reason::DEAUTH_LEAVING },
        }
    }

    /// Record a beacon from the network. # C: O(1)
    pub fn note_beacon(&mut self, now_ns: u64) {
        self.beacons_missed = 0;
        self.last_beacon_ns = now_ns;
    }

    /// Whether the link has gone quiet long enough to be considered lost.
    /// # C: O(1)
    pub fn beacon_lost(&self, beacon_int_tu: u16, now_ns: u64) -> bool {
        if self.step != MlmeStep::Associated || self.last_beacon_ns == 0 { return false; }
        let interval = limits::tu_to_ns(beacon_int_tu.max(1) as u64);
        now_ns.saturating_sub(self.last_beacon_ns)
            >= interval * limits::BEACON_LOSS_COUNT as u64
    }

    /// Whether the link is quiet enough to be worth probing before giving up.
    /// # C: O(1)
    pub fn should_probe(&self, beacon_int_tu: u16, now_ns: u64) -> bool {
        if self.step != MlmeStep::Associated || self.last_beacon_ns == 0 { return false; }
        let interval = limits::tu_to_ns(beacon_int_tu.max(1) as u64);
        let quiet = now_ns.saturating_sub(self.last_beacon_ns);
        quiet >= interval * limits::PROBE_START_COUNT as u64
            && quiet < interval * limits::BEACON_LOSS_COUNT as u64
    }

    /// Whether the interface is associated. # C: O(1)
    pub fn is_associated(&self) -> bool { self.step == MlmeStep::Associated }
}
