// Which denials a layer reports.
//
// Three independent switches per enforced layer, all set once at the moment
// the layer is enforced and never afterwards:
//   - whether denials in the SAME execution are reported,
//   - whether denials AFTER a new execution are reported,
//   - whether layers stacked on top of this one may report at all.
//
// The first two exist because a sandbox usually knows exactly which of its own
// accesses it expects to be refused, and reporting those would bury the ones
// it did not expect. The third exists because a process that sandboxes a child
// must be able to stop the child from filling the log on its behalf.
//
// Pure: no task state, no audit system. `audit` reads these to decide.

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::uapi::*;

/// Whether a layer's denials can reach the log at all.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LogStatus {
    /// Reportable, and the layer has not yet been described in the log.
    Pending,
    /// Reportable, and the layer has already been described once.
    Recorded,
    /// Never reported: the layer asked for silence, or an ancestor did on its
    /// behalf.
    Disabled,
}

/// The reporting configuration one enforced layer carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LogConfig {
    pub status: LogStatus,
    /// Report denials incurred by the execution that enforced this layer.
    pub same_exec: bool,
    /// Report denials incurred after a later execution.
    pub new_exec: bool,
}

impl Default for LogConfig {
    /// The defaults a layer gets when its enforcement named no logging flag:
    /// report what this execution is refused, and stop at the next `execve`.
    /// A sandbox is written for the program that installs it, so a denial
    /// after the program is replaced usually describes a different policy
    /// problem and belongs to whoever asked for it.
    /// # C: O(1)
    fn default() -> Self {
        Self { status: LogStatus::Pending, same_exec: true, new_exec: false }
    }
}

impl LogConfig {
    /// Read the configuration out of `landlock_restrict_self` flags.
    ///
    /// `parent_allows_subdomains` is false once any ancestor enforcement asked
    /// that the layers beneath it stay silent; that decision is inherited and
    /// cannot be revoked by the layer it silences, which is what makes it
    /// usable for confining a child.
    /// # C: O(1)
    pub fn from_flags(flags: u32, parent_allows_subdomains: bool) -> Self {
        let same_exec = (flags & RESTRICT_SELF_LOG_SAME_EXEC_OFF) == 0;
        let new_exec = (flags & RESTRICT_SELF_LOG_NEW_EXEC_ON) != 0;
        // A layer that reports in neither execution reports never; recording
        // that as the status rather than as two false flags means the denial
        // path can stop at one test.
        let status = if (!same_exec && !new_exec) || !parent_allows_subdomains {
            LogStatus::Disabled
        } else {
            LogStatus::Pending
        };
        Self { status, same_exec, new_exec }
    }

    /// Whether a denial is reported, given whether the layer was enforced by
    /// the execution that hit it.
    /// # C: O(1)
    pub fn reports(&self, same_execution: bool) -> bool {
        if self.status == LogStatus::Disabled { return false; }
        if same_execution { self.same_exec } else { self.new_exec }
    }
}

/// Who built a layer, for the record that describes it once.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainDetails {
    pub pid: u32,
    pub uid: u32,
    /// Path of the executable that enforced the layer.
    pub exe: alloc::vec::Vec<u8>,
    /// Command name of the thread that enforced it.
    pub comm: alloc::vec::Vec<u8>,
}

/// The live reporting state of one enforced layer.
///
/// Shared by reference, not copied: stacking a layer clones the layers beneath
/// it, and a copied "already described" flag would make every stacking
/// re-describe the same domain — and split the denial count across copies of
/// what is one layer.
pub struct LayerLog {
    pub cfg: LogConfig,
    pub details: DomainDetails,
    /// `LogStatus` as an atomic, because it moves from pending to recorded
    /// from a denial path that holds only a shared reference.
    status: AtomicU32,
    denials: AtomicU64,
}

const STATUS_PENDING:  u32 = 0;
const STATUS_RECORDED: u32 = 1;
const STATUS_DISABLED: u32 = 2;

impl LayerLog {
    /// # C: O(1)
    pub fn new(cfg: LogConfig, details: DomainDetails) -> Self {
        let status = match cfg.status {
            LogStatus::Pending => STATUS_PENDING,
            LogStatus::Recorded => STATUS_RECORDED,
            LogStatus::Disabled => STATUS_DISABLED,
        };
        Self { cfg, details, status: AtomicU32::new(status), denials: AtomicU64::new(0) }
    }

    /// # C: O(1)
    pub fn status(&self) -> LogStatus {
        match self.status.load(Ordering::Acquire) {
            STATUS_RECORDED => LogStatus::Recorded,
            STATUS_DISABLED => LogStatus::Disabled,
            _ => LogStatus::Pending,
        }
    }

    /// Whether a denial reaches the log.
    /// # C: O(1)
    pub fn reports(&self, same_execution: bool) -> bool {
        if self.status() == LogStatus::Disabled { return false; }
        if same_execution { self.cfg.same_exec } else { self.cfg.new_exec }
    }

    /// Count one denial. Counted whatever the reporting decision is: a policy's
    /// author wants to know how often a layer refuses even while the log is
    /// quiet, and the count is what the teardown record carries.
    /// # C: O(1)
    pub fn count_denial(&self) { self.denials.fetch_add(1, Ordering::Relaxed); }

    /// # C: O(1)
    pub fn denials(&self) -> u64 { self.denials.load(Ordering::Relaxed) }

    /// Claim the right to describe this layer, once. Returns the status BEFORE
    /// the claim, so exactly one caller sees `Pending` and writes the record.
    /// # C: O(1)
    pub fn claim_description(&self) -> LogStatus {
        match self.status.compare_exchange(STATUS_PENDING, STATUS_RECORDED,
            Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => LogStatus::Pending,
            Err(STATUS_RECORDED) => LogStatus::Recorded,
            Err(_) => LogStatus::Disabled,
        }
    }
}

/// Whether the layers stacked on top of this enforcement may report.
///
/// One-way: once an enforcement asks for silence beneath it, no later
/// enforcement in the same thread can restore reporting — otherwise a
/// sandboxed child could simply undo its parent's decision.
/// # C: O(1)
pub fn subdomains_allowed(parent_allows: bool, flags: u32) -> bool {
    parent_allows && (flags & RESTRICT_SELF_LOG_SUBDOMAINS_OFF) == 0
}

// ---- per-thread reporting state -------------------------------------------
//
// One word on the thread, because both halves are per-thread rather than
// per-domain: the enforced-layer set is cleared by `execve` while the domain
// survives it, and the subdomain switch can be set by an enforcement that
// installs no layer at all.

/// Top bit: some enforcement in this thread asked the layers beneath it to
/// stay silent.
const SUBDOMAINS_OFF: u32 = 1 << 31;
/// Low bits: layer levels this execution enforced.
const EXEC_LAYERS_MASK: u32 = (1 << MAX_NUM_LAYERS) - 1;

/// Layer levels the current execution enforced.
/// # C: O(1)
pub fn exec_layers(state: u32) -> u32 { state & EXEC_LAYERS_MASK }

/// Whether layers stacked from here on may report.
/// # C: O(1)
pub fn state_allows_subdomains(state: u32) -> bool { state & SUBDOMAINS_OFF == 0 }

/// The state after an enforcement with `flags` that installed `layer` (or
/// installed none, when `layer` is `None`).
///
/// The subdomain switch is applied whether or not a layer was installed: an
/// enforcement naming only that flag is exactly how a launcher silences the
/// sandbox it is about to hand to a child.
/// # C: O(1)
pub fn state_after_restrict(state: u32, flags: u32, layer: Option<usize>) -> u32 {
    let mut out = state;
    if !subdomains_allowed(state_allows_subdomains(state), flags) { out |= SUBDOMAINS_OFF; }
    if let Some(l) = layer { if l < MAX_NUM_LAYERS { out |= 1 << l; } }
    out
}

/// The state a newly executed program starts from: it enforced no layer, and
/// the subdomain switch survives because it was a decision about the layers,
/// not about the program that made it.
/// # C: O(1)
pub fn state_after_exec(state: u32) -> u32 { state & !EXEC_LAYERS_MASK }

#[cfg(test)]
#[path = "tests/logging.rs"]
mod tests;
