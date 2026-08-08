// Record bodies for the kernel-side producers that are not part of the audit
// system itself. Formatting lives here rather than in each producer so the
// record layout has one owner; the producer supplies the facts.

extern crate alloc;

use alloc::vec::Vec;

use crate::emit::{self, Admitted, Refusal};
use crate::fmt;
use crate::uapi::{AUDIT_FANOTIFY, AUDIT_SECCOMP};

/// The justification a permission daemon attached to its verdict: which of its
/// rules decided, and how far it trusts each side.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FanotifyInfo {
    pub rule_number: u32,
    pub subj_trust: u32,
    pub obj_trust: u32,
}

/// `FAN_RESPONSE_INFO_NONE` — the verdict carried no justification.
pub const FAN_RESPONSE_INFO_NONE: u8 = 0;
/// `FAN_RESPONSE_INFO_AUDIT_RULE` — the verdict named a rule.
pub const FAN_RESPONSE_INFO_AUDIT_RULE: u8 = 1;

/// A trust value the daemon did not state. The field is tri-valued — no, yes,
/// unknown — so an absent justification reports unknown rather than no.
const TRUST_UNKNOWN: u32 = 2;

/// Body of a permission-verdict record.
///
/// `info` is `None` when the daemon answered without a justification: the
/// record is still written, because "a daemon decided this and would not say
/// why" is itself what an auditor needs to see.
/// # C: O(1)
pub fn fanotify_body(response: u32, info: Option<FanotifyInfo>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"resp=");
    fmt::dec(&mut b, response as u64);
    b.extend_from_slice(b" fan_type=");
    match info {
        None => {
            fmt::dec(&mut b, FAN_RESPONSE_INFO_NONE as u64);
            b.extend_from_slice(b" fan_info=0 subj_trust=");
            fmt::dec(&mut b, TRUST_UNKNOWN as u64);
            b.extend_from_slice(b" obj_trust=");
            fmt::dec(&mut b, TRUST_UNKNOWN as u64);
        }
        Some(i) => {
            fmt::dec(&mut b, FAN_RESPONSE_INFO_AUDIT_RULE as u64);
            b.extend_from_slice(b" fan_info=");
            fmt::hex_upper(&mut b, i.rule_number as u64);
            b.extend_from_slice(b" subj_trust=");
            fmt::dec(&mut b, i.subj_trust as u64);
            b.extend_from_slice(b" obj_trust=");
            fmt::dec(&mut b, i.obj_trust as u64);
        }
    }
    b
}

/// Log a permission verdict the daemon asked to have audited.
/// # C: O(1)
pub fn log_fanotify(response: u32, info: Option<FanotifyInfo>) -> Result<Admitted, Refusal> {
    emit::log(AUDIT_FANOTIFY, &fanotify_body(response, info))
}

/// The facts a syscall filter's decision carries.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SeccompEvent {
    pub tid: u32,
    /// Signal the filter raised, or zero.
    pub signal: u32,
    /// The filter's action word.
    pub action: u32,
    pub syscall: i32,
    /// Audit architecture token of the calling thread.
    pub arch: u32,
    /// Instruction pointer of the call.
    pub ip: u64,
    /// Errno the filter returned, or zero.
    pub errno: u32,
}

/// Body of a syscall-filter record.
/// # C: O(1)
pub fn seccomp_body(e: SeccompEvent) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"pid=");
    fmt::dec(&mut b, e.tid as u64);
    b.extend_from_slice(b" sig=");
    fmt::dec(&mut b, e.signal as u64);
    b.extend_from_slice(b" arch=");
    fmt::hex(&mut b, e.arch as u64);
    b.extend_from_slice(b" syscall=");
    fmt::dec_signed(&mut b, e.syscall as i64);
    b.extend_from_slice(b" ip=");
    fmt::hex(&mut b, e.ip);
    b.extend_from_slice(b" code=");
    fmt::hex(&mut b, e.action as u64);
    b.extend_from_slice(b" res=");
    fmt::dec(&mut b, e.errno as u64);
    b
}

/// Log a syscall-filter decision. Only logged while audit is on: a filter that
/// fires on every call of a hot syscall would otherwise fill the hold queue on
/// a system with no consumer at all.
/// # C: O(1)
pub fn log_seccomp(e: SeccompEvent) -> Result<Admitted, Refusal> {
    emit::log_if_enabled(AUDIT_SECCOMP, &seccomp_body(e))
}

#[cfg(test)]
#[path = "tests/producers.rs"]
mod tests;
