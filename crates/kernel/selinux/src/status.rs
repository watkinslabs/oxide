// Global security-server state: whether SELinux is enabled at all, whether it
// enforces or merely reports, and the sequence number that invalidates cached
// decisions across a policy reload.
//
// Enabled-ness is decided once at boot and never changes; enforcing-ness is
// mutable at runtime. Conflating the two is how a system that was booted with
// the module disabled ends up reporting "permissive" to userspace and being
// asked to load a policy it has no table for.

use crate::error::{Error, Result};

/// Whether denials are refused or only reported.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Enforcing {
    /// Denials are reported and allowed through.
    Permissive,
    /// Denials are refused.
    Enforcing,
}

impl Enforcing {
    /// Decode the value userspace writes to the enforcement control. # C: O(1)
    pub const fn from_flag(v: i32) -> Self {
        if v != 0 { Self::Enforcing } else { Self::Permissive }
    }

    /// Value userspace reads back from the enforcement control. # C: O(1)
    pub const fn as_flag(self) -> i32 {
        match self { Self::Enforcing => 1, Self::Permissive => 0 }
    }

    /// Whether a denial must be refused. # C: O(1)
    pub const fn refuses(self) -> bool { matches!(self, Self::Enforcing) }
}

/// Boot-time disposition parsed from the kernel command line.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BootConfig {
    /// Whether the security server runs at all.
    pub enabled: bool,
    /// Initial enforcement state, when the command line states one.
    pub enforcing: Option<Enforcing>,
}

impl Default for BootConfig {
    fn default() -> Self { Self { enabled: true, enforcing: None } }
}

/// Parse the boot parameters that configure the security server. # C: O(line)
///
/// The module is ON unless the command line switches it off; a distribution
/// that ships a policy expects a kernel that will load it. `enforcing=` states
/// the initial mode when present, and its absence means the mode comes from
/// the policy's own permissive settings and userspace's later write, NOT from
/// a hard-coded default here.
pub fn parse_boot_config(value_of: impl Fn(&[u8]) -> Option<&'static [u8]>,
                         bare_flag: impl Fn(&[u8]) -> bool) -> BootConfig {
    let enabled = match value_of(b"selinux") {
        Some(b"0") => false,
        Some(_) => true,
        None => !bare_flag(b"noselinux"),
    };
    let enforcing = match value_of(b"enforcing") {
        Some(b"0") => Some(Enforcing::Permissive),
        Some(_) => Some(Enforcing::Enforcing),
        None => if bare_flag(b"enforcing") { Some(Enforcing::Enforcing) } else { None },
    };
    BootConfig { enabled, enforcing }
}

/// Mutable security-server state that lives beside the loaded policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SecurityState {
    /// Whether the security server runs at all.
    pub enabled: bool,
    /// Whether a policy has been loaded.
    pub initialized: bool,
    /// Current enforcement mode.
    pub enforcing: Enforcing,
    /// Bumped on every policy load and boolean commit.
    pub seqno: u32,
    /// Bumped on every policy load, for the userspace status page.
    pub policyload: u32,
    /// SEQLOCK for the userspace status page — NOT [`SecurityState::seqno`].
    ///
    /// Userspace treats an ODD value as "the kernel is rewriting this page,
    /// come back", and spins — the reference's reader yields the CPU until it
    /// turns even. So this counter must be EVEN whenever the page is
    /// readable, which means it advances by two per update: the reference
    /// increments it once before writing the fields and once after, and this
    /// port renders the whole page from one consistent snapshot, so the
    /// in-progress half is never observable and both halves land together.
    ///
    /// Publishing `seqno` here instead is what wedged every boot that loaded a
    /// policy: `seqno` counts updates one at a time, so a single policy load
    /// left it at 1 — permanently odd — and `libselinux` yielded 5.7 million
    /// times a second, forever, in PID 1.
    pub status_seq: u32,
}

/// Amount [`SecurityState::status_seq`] advances per completed update: the
/// reference's two seqlock increments, begin and end.
pub const STATUS_SEQ_PER_UPDATE: u32 = 2;

impl SecurityState {
    /// State of a security server that has not yet loaded a policy. # C: O(1)
    pub const fn new(boot: BootConfig) -> Self {
        let enforcing = match boot.enforcing {
            Some(e) => e,
            // Before a policy is loaded there is nothing to enforce, so the
            // pre-load mode is permissive regardless; the policy load applies
            // the real mode.
            None => Enforcing::Permissive,
        };
        Self { enabled: boot.enabled, initialized: false, enforcing, seqno: 0, policyload: 0,
               status_seq: 0 }
    }

    /// Whether a check must be answered from policy rather than allowed. # C: O(1)
    ///
    /// Before the first policy load there IS no policy, so every check is
    /// allowed. That is not a permissive mode: it is the bootstrap window in
    /// which the tables do not exist, and treating it as a decision would deny
    /// the very process that loads the policy.
    pub const fn consults_policy(&self) -> bool { self.enabled && self.initialized }

    /// Record a policy load, invalidating every cached decision. # C: O(1)
    pub fn note_policy_load(&mut self) {
        self.initialized = true;
        self.seqno = self.seqno.wrapping_add(1);
        self.policyload = self.policyload.wrapping_add(1);
        self.status_seq = self.status_seq.wrapping_add(STATUS_SEQ_PER_UPDATE);
    }

    /// Record a boolean commit, invalidating every cached decision. # C: O(1)
    pub fn note_bool_commit(&mut self) {
        self.seqno = self.seqno.wrapping_add(1);
        self.status_seq = self.status_seq.wrapping_add(STATUS_SEQ_PER_UPDATE);
    }

    /// Change the enforcement mode. # C: O(1)
    ///
    /// The status page carries the mode, so a change to it is an update of
    /// that page and advances its seqlock — the reference has a dedicated
    /// setenforce notifier for exactly this. Without the bump a reader that
    /// caches by sequence keeps answering with the old mode.
    pub fn set_enforcing(&mut self, e: Enforcing) -> Result<()> {
        if !self.enabled { return Err(Error::InvalidContext); }
        if self.enforcing != e { self.status_seq = self.status_seq.wrapping_add(STATUS_SEQ_PER_UPDATE); }
        self.enforcing = e;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/status.rs"]
mod tests;
