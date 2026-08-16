// The `SYSTEM_SUSPEND` admission ladder and call-result decode (`32a§9`).
//
// UNGATED on purpose. Every decision below is what decides whether
// `/sys/power/state` offers `mem` on this machine, and whether a firmware
// return means "asleep and back" or "refused". Both belong somewhere a hosted
// test can fail; the conduit asm that feeds them lives in `psci.rs`.

use crate::psci_uapi::{decode_status, version_major, PsciStatus, PSCI_RET_NOT_SUPPORTED};

/// What the probe learned about `SYSTEM_SUSPEND` on this platform.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SuspendSupport {
    /// No probe has run yet. Admits nothing — an unprobed platform is not a
    /// supporting one.
    Unprobed,
    /// Firmware predates PSCI 1.0, so neither `PSCI_FEATURES` nor
    /// `SYSTEM_SUSPEND` exists to ask about.
    TooOld,
    /// PSCI 1.0+, and `PSCI_FEATURES` reports the function absent.
    Unsupported,
    /// PSCI 1.0+, and `PSCI_FEATURES` reports the function present. The word
    /// carries the feature flags the query returned.
    Supported(u32),
}

impl SuspendSupport {
    /// Whether `mem` may be admitted. # C: O(1)
    pub fn admits_mem(self) -> bool { matches!(self, SuspendSupport::Supported(_)) }
}

/// Whether this firmware version is new enough for `PSCI_FEATURES` and
/// `SYSTEM_SUSPEND`. Both arrived in PSCI 1.0, so the major field alone decides;
/// a 0.2 firmware answering the `PSCI_FEATURES` function ID is answering a
/// function it does not implement and its result carries no information.
/// # C: O(1)
pub fn version_has_features(version_raw: u32) -> bool {
    version_major(version_raw) >= 1
}

/// Decode a `PSCI_FEATURES` result. The interface returns a non-negative
/// feature-flags word when the queried function exists and `NOT_SUPPORTED` when
/// it does not, so `NOT_SUPPORTED` — and only `NOT_SUPPORTED` — means absent.
/// # C: O(1)
pub fn feature_present(features_raw: i64) -> bool {
    features_raw != PSCI_RET_NOT_SUPPORTED
}

/// The full admission ladder: version gate first, then the feature query.
/// Ordering matters — the query is only meaningful once the version says the
/// query itself exists.
/// # C: O(1)
pub fn classify_support(version_raw: u32, features_raw: i64) -> SuspendSupport {
    if !version_has_features(version_raw) { return SuspendSupport::TooOld; }
    if !feature_present(features_raw) { return SuspendSupport::Unsupported; }
    SuspendSupport::Supported(features_raw as u32)
}

/// Decode a `SYSTEM_SUSPEND` return. The call only returns at all when it
/// failed — a successful suspend resumes at the entry point instead — so a
/// `Success` word coming back out of the call is itself a firmware defect and
/// is reported as one rather than as a completed sleep.
/// # C: O(1)
pub fn suspend_call_result(raw: i64) -> Result<(), PsciStatus> {
    match decode_status(raw as i32) {
        PsciStatus::Success => Err(PsciStatus::Success),
        other => Err(other),
    }
}

/// Why a suspend attempt could not even be made, ahead of the firmware call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SuspendRefusal {
    /// The probe does not admit `mem` on this platform.
    Unsupported,
    /// The physical resume entry point could not be resolved.
    NoResumeEntry,
    /// The identity translation table the resume entry needs to turn the MMU
    /// back on was never published, so the entry would fault the instruction
    /// after `SCTLR_EL1.M` is set.
    NoIdentityTable,
    /// The saved-context block has no physical address, so firmware could not
    /// be handed a context identifier the resume entry can dereference.
    NoContextAddress,
}

/// Pre-call gate: everything that must be true before firmware is asked.
/// Checked in this order so the most specific missing piece is what gets
/// reported.
/// # C: O(1)
pub fn preflight(support: SuspendSupport, entry_pa: u64, identity_ttbr0_pa: u64, ctx_pa: u64)
    -> Result<(), SuspendRefusal>
{
    if !support.admits_mem() { return Err(SuspendRefusal::Unsupported); }
    if entry_pa == 0 { return Err(SuspendRefusal::NoResumeEntry); }
    if identity_ttbr0_pa == 0 { return Err(SuspendRefusal::NoIdentityTable); }
    if ctx_pa == 0 { return Err(SuspendRefusal::NoContextAddress); }
    Ok(())
}

/// Tag values for the cached probe word. Zero is `Unprobed` so a freshly
/// zeroed cache means "nobody has asked yet", never "supported".
const TAG_UNPROBED:    u64 = 0;
const TAG_TOO_OLD:     u64 = 1;
const TAG_UNSUPPORTED: u64 = 2;
const TAG_SUPPORTED:   u64 = 3;
const TAG_SHIFT:       u64 = 32;
const FLAGS_MASK:      u64 = 0xFFFF_FFFF;

/// Pack a probe result into one word so it can live in a single atomic.
/// # C: O(1)
pub fn encode_support(s: SuspendSupport) -> u64 {
    match s {
        SuspendSupport::Unprobed       => TAG_UNPROBED << TAG_SHIFT,
        SuspendSupport::TooOld         => TAG_TOO_OLD << TAG_SHIFT,
        SuspendSupport::Unsupported    => TAG_UNSUPPORTED << TAG_SHIFT,
        SuspendSupport::Supported(f)   => (TAG_SUPPORTED << TAG_SHIFT) | f as u64,
    }
}

/// Unpack a cached probe word. An unrecognised tag reads as `Unprobed`, which
/// admits nothing.
/// # C: O(1)
pub fn decode_support(w: u64) -> SuspendSupport {
    match w >> TAG_SHIFT {
        TAG_TOO_OLD     => SuspendSupport::TooOld,
        TAG_UNSUPPORTED => SuspendSupport::Unsupported,
        TAG_SUPPORTED   => SuspendSupport::Supported((w & FLAGS_MASK) as u32),
        _               => SuspendSupport::Unprobed,
    }
}

#[cfg(test)]
#[path = "psci_probe/tests.rs"]
mod tests;
