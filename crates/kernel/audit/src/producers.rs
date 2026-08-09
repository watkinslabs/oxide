// Record bodies for the kernel-side producers that are not part of the audit
// system itself. Formatting lives here rather than in each producer so the
// record layout has one owner; the producer supplies the facts.

extern crate alloc;

use alloc::vec::Vec;

use crate::emit::{self, Admitted, Refusal};
use crate::fmt;
use crate::tty;
use crate::uapi::{AUDIT_FANOTIFY, AUDIT_SECCOMP, AUDIT_TTY};

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

/// Who read the terminal input a record accounts for.
///
/// Every field is supplied by the caller: this crate reads no task. `auid` and
/// `ses` are the login identity the input is attributed to, which is the whole
/// point of the record — the effective uid of a shell says nothing about which
/// human typed into it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TtyActor<'a> {
    pub pid: u32,
    pub uid: u32,
    pub auid: u32,
    pub ses: u32,
    /// Command name, as read from the task. Untrusted: a process names itself.
    pub comm: &'a [u8],
}

/// `tty` — buffered terminal input.
pub const TTY_DESC_INPUT: &[u8] = b"tty";
/// `ioctl=TIOCSTI` — a byte pushed into a terminal's input queue by ioctl
/// rather than typed, which is a way to make another process run a command.
pub const TTY_DESC_TIOCSTI: &[u8] = b"ioctl=TIOCSTI";

/// Body of a terminal-input record.
///
/// `data` is always hex, never quoted: it is raw terminal input, so it
/// routinely holds control bytes, and an encoding that varied with the content
/// would let input choose how it is framed.
/// # C: O(comm len + data len)
pub fn tty_body(desc: &[u8], a: TtyActor<'_>, dev: tty::Devno, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(desc);
    b.extend_from_slice(b" pid=");
    fmt::dec(&mut b, a.pid as u64);
    b.extend_from_slice(b" uid=");
    fmt::dec(&mut b, a.uid as u64);
    b.extend_from_slice(b" auid=");
    fmt::dec(&mut b, a.auid as u64);
    b.extend_from_slice(b" ses=");
    fmt::dec(&mut b, a.ses as u64);
    b.extend_from_slice(b" major=");
    fmt::dec(&mut b, dev.major as u64);
    b.extend_from_slice(b" minor=");
    fmt::dec(&mut b, dev.minor as u64);
    b.extend_from_slice(b" comm=");
    fmt::untrusted(&mut b, a.comm);
    b.extend_from_slice(b" data=");
    fmt::hex_bytes(&mut b, data);
    b
}

/// Log one terminal-input record. The caller has already decided that audit is
/// on — a flush empties its buffer whether or not it writes anything, so the
/// enable test belongs to the flush, not here.
/// # C: O(comm len + data len)
pub fn log_tty(desc: &[u8], a: TtyActor<'_>, dev: tty::Devno, data: &[u8])
    -> Result<Admitted, Refusal>
{
    emit::log(AUDIT_TTY, &tty_body(desc, a, dev, data))
}

#[cfg(test)]
#[path = "tests/producers.rs"]
mod tests;
